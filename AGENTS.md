# AGENTS.md

kit is a content-addressed, signed version-control system. Security comes first. Keep the code small.

## Security

- Parse hostile input strictly. Reject malformed, non-canonical and trailing bytes.
- Bound every allocation by a limit that is checked before the allocation, never by a length read from the input.
- Verify before trust. Check hashes, signatures and attestations before you use the data they cover.
- Never write secrets, keys, tokens or passphrases to logs, errors, debug output or test snapshots.
- Do not use `unsafe` without a `// SAFETY:` comment that states the invariant and why it holds.
- Give every domain-separation tag, magic and predicate URI a unique value. Never reuse one across purposes.
- Fail closed. An unknown version, algorithm or field is an error.

## Formats

- A format change updates the spec and the golden vectors in the same commit.
- Golden vectors must pass in the Rust code and in an independent reference check.
- Never change a published tag, magic or constant to fix a style issue.

## Code

- Do not vendor code. Depend on published crates at exact audited versions.
- Do not check in generated output unless a build requires it. If you do, say why next to the file.
- Do not leave dead code. Do not add speculative features, options or abstractions.
- Add a dependency only when the code cannot reasonably do without it.
- Every new behavior needs a test. Every parser needs a fuzz target.
- Run `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test` before you commit.
- Run `scripts/check-writing.sh` and `scripts/check-unsafe-safety.sh` before you commit. CI runs both.

## Writing

- Code, docs, commits and issues must not mention phases, stages, parts, work packages, ticket numbers, PR numbers, trackers, tools or models.
- Describe what the code does now. Do not describe how it got there.
- Write short, active sentences. Use one term for one concept.

## Commits

- Sign every commit.
- Make one logical change per commit.
- Write a subject line of 72 characters or fewer, in the imperative mood.
- Write a body that explains why the change is needed, not only what it does.
- Add no trailers that name a tool or a model.
