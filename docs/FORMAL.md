# Formal verification

kit checks parts of its specifications with formal tools: model
checkers for the concurrent and crash-recovery protocols, a bounded model
checker for the untrusted-input decoders, and a replay harness that ties
one model back to the code. This page says what each check covers, how strong its result
is, what it assumes, and what it found. The per-model READMEs under
[`formal/`](../formal/README.md) hold the full detail: every invariant,
mutant, bound, state count and run time.

The models and harnesses check the current specs. The spec
text is normative. Where a model found the spec wrong, the spec was fixed;
where it found the code wrong, the code was fixed with a regression test,
or the gap is listed under [Open findings](#open-findings).

## How strong is a result

Every result on this page carries one of these labels. Read them
literally.

| Label | Meaning | Tool |
|---|---|---|
| **exhaustive (finite instance)** | Every reachable state of a fixed, small instance (named constants: processes, objects, clock range). Says nothing about larger instances. | TLC |
| **bounded (length k)** | Every execution of at most k steps of a fixed instance, checked symbolically. | Apalache |
| **bounded (input size)** | Every input up to the stated size, checked symbolically by CBMC. | Kani |
| **simulated** | Random executions (for example 20,000 samples of 40 steps, seed `0x1`). Finds bugs; shows nothing about the executions it did not draw. | `quint run` |
| **tested** | Pinned scenarios (`quint test`, Rust tests) or a replay of sampled traces against the code. | quint, cargo |

"Bounded" never means "proved". No result on this page is a proof for
unbounded inputs.

**Non-vacuity.** A property that holds could hold because it is too weak
or because the model never reaches the interesting states. Every
invariant here is therefore paired with evidence that it can fail:

- a **mutant**, a copy of the model with one deliberate bug, which the
  checker must report as a violation of that specific invariant;
- a **canary**, a false reachability claim the checker must refute,
  which shows the states that matter are reached;
- for Kani, a `*_canary_*` harness marked `#[kani::should_panic]`.

Each `check.sh` prints one line per check with its expected outcome
(`ok` or `violation`) and exits 1 on anything unexpected, so a mutant that
stops failing breaks the run just like an invariant that stops holding.

## Tool split

| Layer | Tool (pin) | Used for | Why this tool |
|---|---|---|---|
| Protocol models | [Quint](https://quint-lang.org) 0.32.0 | Ref CAS and lock order, the recovery log, history publication and crash recovery | Concurrency, crashes and retries are state-machine properties. Quint gives typed, executable models with `quint test` scenarios and fast random simulation, and compiles to TLA+ for the model checkers. |
| Model checking | Apalache 0.62.2, TLC (the `tlc2.TLC` class inside the Apalache jar), Java 21 | Bounded symbolic (Apalache) and exhaustive explicit-state (TLC) checks of the compiled Quint models, including TLC liveness under fairness | Apalache is run directly on the TLA+ `quint compile` emits, because `quint verify` bundles an older Apalache (0.56.1) that predates the FoldSet fixes the models rely on. |
| Decoders | Kani 0.68.0 (CBMC 6.11.0) | Panic freedom and spec agreement of `delta`, `merkle`, `pack`, `serialize`, the keystore record and RPC framing on small symbolic inputs | Checks the actual Rust, not a model, which is what matters for untrusted input. The fuzz targets ([FUZZ.md](FUZZ.md)) cover larger inputs by sampling. |
| Conformance | Rust test replaying ITF traces | `refs_mbt.qnt` traces replayed step by step against `kit_core::refs`, `ops::recovery`, `FileTransport` and `MemoryTransport` | Closes the loop from a model to the code for the ref layer: the same step must produce the same refs, recovery log and CAS outcome. |

**Why no standalone TLA+.** The protocol models are written once, in
Quint, and TLA+ is generated from them. Hand-written TLA+ would be a
second copy of each model that could drift from the Quint one that the
tests and simulations use. The only hand-written TLA+ is
`formal/quint/history/tlc/`: thin wrappers that add a state `VIEW` and
fairness to the compiled output. TLC runs as a checker, not as a
modelling language.

## Traceability

One row per property that a spec clause depends on. "Status" is the
strongest label the property has; weaker checks (simulation, scenario
tests) also run on every row. Bounds are the defaults in each
`check.sh`. The linked READMEs list every property; this table lists the
ones a spec reader is most likely to look for.

### Refs, locks and servers ([`formal/quint/refs`](../formal/quint/refs/README.md), ref concurrency model)

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| SPEC-REFS §5, §5.1 (CAS per lock domain) | `NoLostUpdateLocal`, `NoLostUpdateFile`, `NoLostUpdateMem` | exhaustive on two slices of `refs2` (2 processes, one ref, 3.4M and 3.5M states); bounded (length 8) on the full op space | mutants `refs2_noRefLock`, `refs2_noFileLock`, `refs2_memNoMutex` |
| SPEC-REFS §5.1.1 (file transport stripe locks) | none | not modelled. The model's `file` domain is one lock; the code takes the repo lock shared and one stripe lock per ref. `kit-transport-file` unit tests cover the races, and the replay row below covers single-threaded traces | - |
| SPEC-CONCURRENCY §4 (lock order) | `NoDeadlock`, `LockOrderRespected`, `LockOwnership` | as above | `refs3_misorder`, `refs2_racyAcquire` |
| SPEC-CONCURRENCY §3.2 (recovery log) | `ExpireHoldsSuperset`, `NoRecordExpireInterleave` | as above | `refs2_gcSkipTrees` |
| SPEC-CONCURRENCY §2, §3.1 (`serve.lock`, `server.lock`, startup sweep) | `SweepAlone`, `NoLiveUploadSwept`, `OneKitServer`, `UpServersHoldServeShared`, `NoMissedDetection` | exhaustive (`serve2` 18,812 states, `serve3` 152,012) | `serve2_sweepUnlocked`, `serve2_sweepUnderShared`, `serve2_serverSkipsServe`, `serve2_serverLockShared` |
| SPEC-REFS v3 §2, §3 (served names, 512-byte bound) | `RefuseBeforeStorage`, `ExplicitRefusal`, `RefusedWritesNothing`, `ListingServedOnly` | exhaustive (`served`, 66,064 states) | `served_checkAfterRead`, `served_headCheckedLate`, `served_listNoSkip` |
| SPEC-CONCURRENCY §3.1 (documented cross-domain gap) | `WitnessCrossDomainGap`, `WitnessUndetectedLateServer` | reached, as documented | - |
| SPEC-REFS §5 (implementation conformance, ref conformance model) | 5 `refs_mbt.qnt` traces (300 steps, 41 commits) agree with the code after every step | tested | 5 injected adapter faults and 2 tampered traces are each caught; an independent adapter mutant was caught in review |

### History publication and scrub ([`formal/quint/history`](../formal/quint/history/README.md))

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| SPEC-HISTORY-PROOF §4.4 (intent withholds proofs; crash recovery) | `NoProofWhileIntent`, `CurrentMatchesRef`, `ServedMatchesRef`, `FinishOnlyFromRecorded`, `RecoveryEnabled`, `NeverFailsClosed` | exhaustive (commits 1..4, at most 3 generations, any number of crashes; 200,388 states under a bisimulation VIEW); bounded (length 10) | `mutLoadIgnoresTx`, `mutHealTipOnly`, `mutFinishAnyRef`, `mutRawIgnoresTx`, `mutWriteBeforeInvalidate` |
| SPEC-HISTORY-PROOF §1 (generations) | `GenerationFastForwardOnly`, `ServedGenerationFresh`, `FastForwardRetainsGeneration` | as above | `mutRawSkipsInvalidate`, `mutReuseGenOnRewrite`, `mutFreshGenOnFF` |
| SPEC-HISTORY-PROOF §4.2, §4.3 (intent roots) | `IntentRootsRetained` | as above | `mutGcIgnoresIntent`, `mutSkipVerify` |
| SPEC-HISTORY-PROOF §4.4 (recovery completes) | `IntentEventuallyCleared` (liveness, weak fairness, finitely many crashes) | exhaustive (TLC temporal, 400,776 states) | `mutRecoverSkipsPending`, `mutRawIgnoresTx`, and the property fails without `WF(RecoverAttempt)` |
| SPEC-HISTORY-PROOF §4.5 (scrub lap at most 65 publishes, 7-day bound, invalid state forces a full walk) | `ActualPublishBound`, `TimeBound`, `InvalidForcesFull` | exhaustive on scaled constants (1,904 states); bounded (length 8); `realLapBoundTest` checks the real constants for every `verified_through` up to 1,000,000 | `mutWrapWithoutFull`, `mutIgnoreAge`, `mutTrustInvalid`, `scrubLossy`, `scrubClockBack` |
| SPEC-HISTORY-PROOF §4.5 ("fewer than 604800 s") | `WindowOnlyWhenFresh` | bounded (Apalache length 8) and simulated only; the TLC VIEW omits the elapsed time | `mutAgeInclusive` (the pre-fix comparison) |

### Decoders ([`formal/kani`](../formal/kani/README.md))

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| SPEC-DELTA §2, §4 | `delta::decode` never panics; equals the §4 reference algorithm; round-trips | bounded (streams up to 20 bytes, bases up to 4) | `delta_decode_canary_wrong_length` |
| SPEC-OBJECTS §2 to §8, §11 | deserializers never panic; tree-name rule matches §4.1; blob round-trip | bounded (bodies up to 12 bytes) | `serialize_canary_trailing_byte_accepted` |
| SPEC-MERKLE-OBJECTS §5.2 to §5.5 | proof decode, verify fold, builder round-trip; §5.4 builder refusal on the empty tree | bounded (0 to 2 siblings, leaf counts up to 8; any `u32` for `s0` and the empty-tree harness) | `merkle_canary_tampered_leaf_verifies` |
| SPEC-PACKFILE §1 to §3, §6, §8, §11 | pack parsing never panics and honors the header, trailer and entry count; window cursor decode | bounded (entry areas of 5 and 10 bytes; one fixed cursor layout of 125 bytes) | `pack_canary_mutation_still_parses`, `pack_window_cursor_canary_flip_accepted` |
| SPEC-KEYSTORE §6.1.1 | record decode never panics; round-trip; id `0x04` rejected | bounded (inputs up to 15 bytes) | `software_key_record_canary_trailing_byte_accepted` |
| SPEC-RPC §1 | `read_frame` never panics; accepts iff full prefix, in-cap length, full body | bounded (streams up to 6 bytes) | `rpc_canary_over_cap_length_accepted` |

## Assumptions

Each result holds only under these assumptions. They are stated in the
model or harness that relies on them.

- **Hashes.** Kani harnesses replace BLAKE3 with a deterministic mixer
  and stub zstd decompression.
- **Bounds.** Every Quint result is for the fixed instance in its README:
  a handful of processes (2 or 3), objects, commits and clock values.
  Apalache lengths are 8 to 10 steps. Kani inputs are a
  few bytes to 125 bytes. Constants are scaled where the real ones are
  too large (for example the scrub model uses `MIN_WINDOW=2` for 512 and
  `MAX_AGE=3` for seven days, keeping the relation that matters, and a
  separate test checks the real constants).
- **Time and crashes.** Time is a small integer clock. Lock waits never
  time out. A crash is one atomic step that discards volatile state;
  history recovery liveness assumes finitely many crashes and fair
  callers.
- **Abstractions of the code.** Each model follows specific Rust
  functions, named in its README, and abstracts I/O: a durable write is
  one step, a lock is a set membership. A mismatch between a model step
  and the code it names is a modelling error these checks cannot catch;
  reviews compared each model with the code
  by hand, and the ref conformance replay checks one model against the code.

## Findings

What the models found, and where each stands. "Fixed" means the code
changed, with a regression test that fails before the fix and passes
after.

### Fixed in code

| Finding name | Finding | Found by | Fix |
|---|---|---|---|
| Empty-tree range proof | The range-proof builder returned the all-default proof for `0..=0` of the empty Tree; SPEC-MERKLE-OBJECTS §5.4 requires a refusal | Kani `merkle_builder_empty_tree_refuses` | `BmtTree::range_proof` refuses every range of the empty tree |
| Scrub age boundary | The scrub took the window path at exactly 604800 s; SPEC-HISTORY-PROOF §4.5 says "fewer than" | `scrub::WindowOnlyWhenFresh` | `decide_chain` compares with `>=` |
| Cached-closure freshness | Cached git translations skipped refreshing the reachable objects | code reading; cached-reuse regressions | [`Importer::reuse_closure`](../rust/crates/kit-git-bridge/src/import.rs) traverses the complete cached closure through `reuse_object` before memoizing it. |
| Read-only reuse | Reused read-only object files failed the commit fsync with `EACCES` | read-only reuse regression | [`sync_reused_file`](../rust/crates/kit-core/src/store.rs) opens reused files read-only on Unix before `sync_all`; platforms requiring write access retain that requirement. |

### Fixed in the spec

The models also found spec text that was wrong or incomplete, and the
spec was corrected: the scrub lap is at most 65 publishes,
not 64, and that bound needs the scrub write to land (SPEC-HISTORY-PROOF
§4.5); SPEC-MERKLE-OBJECTS §5.4 states the builder refusal. The per-model READMEs list each change.

### Open findings

These findings and exclusions remain open within the stated model bounds.

| Finding name or model | Severity | Finding | Evidence |
|---|---|---|---|
| GC grace and clock assumptions | hypothesis | Refresh and final unlink exclude each other, but a newly reachable object still needs `T - mtime < grace` until root publication. Expired or zero grace and clock skew can violate that condition. | SPEC-GC "Concurrent writers and the grace window" |
| ref conformance model | coverage | The conformance fixtures reach no successful `amend` commit and no memory-transport `Any` write | fixture tally |

## Limitations

- **Bounded is not proved.** Every result covers a finite
  instance, a bounded length or a bounded input size. Larger instances
  are argued, not checked; several READMEs record checks that did not
  finish within the 30-minute budget and were cut back.
- **Not everything is checked by every tool.** Some invariants are checked
  only by simulation and Apalache (for example `WindowOnlyWhenFresh`), some
  liveness properties only on the smaller instances, and some mutants only by `quint run` and TLC. The per-model
  READMEs say which.
- **Models follow the code by hand.** Only the refs model is replayed
  against the implementation, and only for 5 sampled traces.
  Lock steps, the `history-mmr` ancestry path and age-based recovery
  pruning are not compared.
- **Not modelled.** Among others: gc, pack GC, the git bridge locks,
  multi-entry trees in Kani, and
  every decoder input beyond the Kani bounds (left to fuzzing and
  proptests).
- **Tool trust.** Results trust Quint's compiler to TLA+, Apalache, TLC,
  and CBMC. Tool versions are pinned; the Apalache jar is
  checked by sha256.

## Run the checks

The scripts under [`formal/scripts`](../formal/scripts) run the layers.
[`.github/workflows/formal.yml`](../.github/workflows/formal.yml) runs the
same scripts nightly and on `workflow_dispatch`, except `run-kani.sh`, which
a developer runs by hand (see [Resource use](#resource-use)). Each script prints one line
per check and fails on any unexpected outcome. Times below are from a shared
15-core arm64 Mac. The Quint layer takes about an hour, which is why the
checks run nightly and not on every pull request. Most of that time is the
`quint run` simulations of the refs model.

| Command | What it runs | Time (developer machine) |
|---|---|---|
| `bash formal/scripts/run-quint.sh` | every `formal/quint/*/check.sh` in its default mode: quint typecheck, test and run, plus TLC where the script runs it by default. `--all` adds the TLC runs that a script leaves off by default. | history 5 to 6 min, refs 26 to 40 min |
| `bash formal/scripts/run-kani.sh` | every Kani harness, one at a time (`KANI_FILTER=regex` to pick some) | about 1.5 h |
| `cargo test -p kit-formal-conformance` (in `rust/`) | the conformance replay: offline, checked-in traces | seconds after the build |
| `CHECK=1 bash formal/scripts/gen-refs-traces.sh` | regenerate the conformance traces from the model and diff them | about 3 min |

### Install the tools

The pins live in `formal/scripts/setup-apalache.sh` (Apalache) and
`formal.yml` (Quint) and `formal/scripts/run-kani.sh` (Kani).

On macOS:

```sh
brew install openjdk@21 jq node
npm install -g @informalsystems/quint@0.32.0
bash formal/scripts/setup-apalache.sh   # Apalache 0.62.2 into ~/.local/share/kit-fv, sha256-checked
cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup
```

The `check.sh` scripts find Homebrew's keg-only `openjdk@21` on their
own.

On Linux, install a Java 21 JDK (for example `apt install
openjdk-21-jdk-headless`) and set `JAVA_HOME` to it, install Node.js and
`jq`, then run the same `npm`, `setup-apalache.sh` and `cargo install`
commands.

`FV_HOME` (default `~/.local/share/kit-fv`) moves the Apalache install;
`APALACHE_MC` and `TLA2TOOLS` point at another copy. Each `check.sh`
documents its own knobs (`ONLY`, `SEL`, `TLC_HEAP`, `*_DEPTH`).

### Resource use

TLC runs with a 4 GB heap and 2 to 4 workers, Apalache with 4 GB. Kani
harnesses peak at up to 63 GB (`pack_writer_roundtrip_raw`), so CI does
not run them. Run `run-kani.sh` by hand on a machine with at least 64 GB.
Run one Kani harness at a time. The recorded times come from a 15-core arm64 Mac shared with other
jobs; a CI runner is slower.
