# Local CI parity. Each `ci-*` recipe runs commands that cloudbuild/ci.yaml
# or cloudbuild/supply.yaml runs, so the recipes hold no logic of their own.
# Change a recipe when the matching Cloud Build step changes.
#
# Run `just ci` for every recipe. Run one recipe to check one gate.
#
# Four Cloud Build parts have no recipe here:
#   - the sccache and mold setup, which only speeds up the build;
#   - the three-way split of the nextest run, which `ci-test` runs as one;
#   - the fuzz smoke runs with the pinned nightly toolchain;
#   - the commit message scan of the `writing` step, which needs `origin/main`.
# The third-party notices, release artifact and publish dry run steps of
# cloudbuild/supply.yaml also have no recipe.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Run every gate.
ci: ci-lint ci-test ci-docs ci-scripts ci-unsafe ci-supply ci-workflows

# The `fmt` and `lint` steps of cloudbuild/ci.yaml.
ci-lint:
    #!/usr/bin/env bash
    set -euo pipefail
    ( cd rust && cargo fmt --check )
    cd rust
    cargo fetch --locked
    cargo clippy --locked --all-targets --all-features --workspace -- -D warnings
    for crate in $(cargo metadata --locked --no-deps --format-version 1 \
        | python3 -I -c 'import json, sys; print(*[p["name"] for p in json.load(sys.stdin)["packages"]])'); do
      cargo clippy --locked --all-targets -p "$crate" -- -D warnings
    done
    msrv=$(awk -F\" '/^[[:space:]]*rust-version[[:space:]]*=/ {print $2; exit}' Cargo.toml)
    rustc_v=$(rustc --version | awk '{print $2}')
    echo "declared minimum=$msrv, rustc=$rustc_v"
    if [ -z "$msrv" ] || [ "$rustc_v" != "$msrv" ]; then
      echo "The active compiler differs from rust-version. Run rustup in rust/." >&2
      exit 1
    fi
    if ! grep -q "channel = \"$msrv\"" rust-toolchain.toml; then
      echo "rust-toolchain.toml does not pin the declared minimum version." >&2
      exit 1
    fi
    cargo check --locked --workspace --all-targets

# The `nextest-*`, `ignored-lane`, `tests-misc`, `version`, `cli-baseline` and `wasm` steps.
ci-test:
    #!/usr/bin/env bash
    set -euo pipefail
    export KIT_TEST_STRICT=1
    ( cd rust && cargo nextest run --locked --workspace --all-features --no-fail-fast --profile ci )
    ( cd rust && cargo nextest run --locked --workspace --all-features --profile ignored-lane --no-fail-fast --run-ignored ignored-only )
    ( cd rust \
      && cargo test --locked --doc --workspace --no-fail-fast \
      && cargo test --locked -p libkit --no-default-features \
      && cargo test --locked -p libkit \
      && cargo test --locked -p libkit --no-default-features --features git-bridge,transport-file,transport-ssh \
      && cargo test --locked -p libkit --no-default-features --features transport-s3,transport-connect,history-mmr,sparse-checkout \
      && cargo test --locked -p libkit --all-features )
    just _version-contract
    bash scripts/check-cli-baseline.sh
    ( cd rust \
      && cargo build --locked -p kit-client --target wasm32-unknown-unknown \
      && cargo build --locked -p kit-client --no-default-features --target wasm32-unknown-unknown )
    ( cd rust \
      && cargo test --locked -p kit-fuzz --no-fail-fast \
      && cargo check --locked -p kit-fuzz --features libfuzzer --bins )

# The `docs` step.
ci-docs:
    ( cd rust && RUSTDOCFLAGS=-Dwarnings cargo doc --locked --workspace --all-features --no-deps )

# The `golden`, `generated` and `writing` steps.
ci-scripts:
    #!/usr/bin/env bash
    set -euo pipefail
    bash scripts/check-spec-status.sh
    python3 -I -B scripts/check-spec-magics.py
    bash scripts/check-crypto-stack-version.sh
    python3 -I -B scripts/check-dependency-versions.py
    bash scripts/test-check-dependency-versions.sh
    python3 -I -B scripts/check-format-constants.py
    bash scripts/test-check-format-constants.sh
    venv=$(mktemp -d)
    trap 'rm -rf "$venv"' EXIT
    python3 -m venv "$venv/ref"
    "$venv/ref/bin/pip" install --require-virtualenv -r scripts/golden/requirements.txt
    PYTHON="$venv/ref/bin/python" bash scripts/check-golden.sh
    bash scripts/check-generated-fresh.sh
    bash scripts/check-writing.sh
    bash scripts/test-check-writing.sh
    bash scripts/check-doc-paths.sh
    bash scripts/test-check-doc-paths.sh
    bash scripts/test-install.sh

# The `unsafe` step.
ci-unsafe:
    #!/usr/bin/env bash
    set -euo pipefail
    bash scripts/check-unsafe-safety.sh
    bash scripts/check-unsafe-policy.sh
    bash scripts/check-geiger-baseline.sh

# The `supply` step, with a deadline search that also runs on macOS.
ci-supply:
    #!/usr/bin/env bash
    set -euo pipefail
    deadline=$(grep -oE 'TODO\([0-9]{4}-[0-9]{2}-[0-9]{2}\)' rust/deny.toml | head -n1 | sed -E 's/TODO\(([0-9-]+)\)/\1/')
    if [ -z "$deadline" ]; then
      echo "rust/deny.toml has no TODO(YYYY-MM-DD) deadline." >&2
      exit 1
    fi
    today=$(date -u +%Y-%m-%d)
    if [[ "$today" > "$deadline" || "$today" == "$deadline" ]]; then
      echo "The advisory ignore in rust/deny.toml expired on $deadline (today: $today)." >&2
      exit 1
    fi
    cd rust
    cargo deny --locked check
    cargo audit --deny warnings \
      --ignore RUSTSEC-2023-0071 \
      --ignore RUSTSEC-2024-0436 \
      --ignore RUSTSEC-2026-0370 \
      --ignore RUSTSEC-2026-0371 \
      --ignore RUSTSEC-2026-0372

# The `workflows` and `ci-gates` steps.
ci-workflows:
    actionlint
    python3 -I -B scripts/test-ci-gates.py

# The `version` step.
_version-contract:
    #!/usr/bin/env bash
    set -euo pipefail
    cd rust
    cargo build --locked -p kit-bin --bin kit
    out=$(./target/debug/kit version)
    expected="kit $(awk -F\" '/^version/ {print $2; exit}' Cargo.toml)"
    echo "stdout:   [$out]"
    echo "expected: [$expected]"
    test "$out" = "$expected"
