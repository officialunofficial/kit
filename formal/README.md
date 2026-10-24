# kit formal models

Formal checks of kit's specifications (formal verification effort). Start with
[`docs/FORMAL.md`](../docs/FORMAL.md): it explains the tool split, what
each result means (proved, exhaustive, bounded, simulated, tested), the
spec-to-property traceability table, the assumptions and the findings.
This directory holds the models; each subdirectory's README has the full
list of properties, mutants, bounds and recorded results.

| Directory | Tool | Covers | Model |
|---|---|---|---|
| [`quint/refs/`](quint/refs/README.md) | Quint, TLC, Apalache | Ref CAS per lock domain, lock order, recovery log, `serve.lock` and `server.lock`, served names; `refs_mbt.qnt` feeds the conformance test | ref concurrency model, ref conformance model |
| [`quint/history/`](quint/history/README.md) | Quint, TLC, Apalache | History publication, crash recovery, the scrub schedule | history publication model |
| [`kani/`](kani/README.md) | Kani | Bounded checks of the untrusted-input decoders (harnesses live next to the Rust code) | decoder harnesses |
| [`scripts/`](scripts/) | quint, jq | `gen-refs-traces.sh`: regenerates the ITF fixtures for `rust/crates/kit-formal-conformance` | ref conformance model |

## Running

From the repository root:

```sh
bash formal/scripts/run-quint.sh      # every quint/*/check.sh, default mode
bash formal/scripts/run-quint.sh --all  # also the TLC runs left off by default
bash formal/scripts/run-kani.sh       # every Kani harness, one at a time
(cd rust && cargo test -p kit-formal-conformance)  # replay the refs traces
```

Each `quint/*/check.sh` also runs on its own (`./check.sh`, see its
header for knobs). Tool pins and install steps are in
[`docs/FORMAL.md`](../docs/FORMAL.md#run-the-checks); the nightly
workflow is [`.github/workflows/formal.yml`](../.github/workflows/formal.yml).

## Conventions for a new model

- Cite the spec section each invariant comes from.
- Give every invariant a mutant or canary that the checker must report
  as violated, and list the expected outcome of each check in the
  model's `check.sh`, which exits 1 on anything unexpected.
- Record bounds, commands and outcomes in the model's README. Never call
  a bounded result proved.
- `formal/scripts/run-quint.sh` picks up any new `quint/<name>/check.sh`
  automatically.
