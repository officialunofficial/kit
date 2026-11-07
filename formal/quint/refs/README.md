# quint-refs: ref CAS, lock order, server locks, served names

Quint models of kit's ref concurrency (formal verification effort), covering the server rules of SPEC-REFS v3 and
SPEC-CONCURRENCY with a layout server. A layout server is a server that embeds the `.kit` filesystem layout.

| File | What it models |
|------|----------------|
| `refs.qnt` | SPEC-REFS §5 CAS (Any / Missing / Match, deletes), §5.1 atomicity per lock domain (local `refs-<ref>.lock`, the file transport's repo and stripe locks, memory `Mutex`), SPEC-REFS §5.1.1 stripe locks, SPEC-CONCURRENCY §4 lock order and deadlock freedom, §3.2 recovery-log record/expire, §3.1 cross-domain gap |
| `refs_test.qnt` | Pinned interleavings for `refs.qnt`, mutants and witnesses included |
| `serve.qnt` | `serveLocks`: `serve.lock` (shared by `kit serve` and a layout server), `server.lock` (exclusive, a layout server), the startup sweep of crashed uploads under an exclusive `serve.lock`, the worktree probe (SPEC-CONCURRENCY §2, §3.1). `servedNames`: SPEC-REFS v3 §2 served names and the §3 512-byte bound, as far as they affect safety |
| `serve_test.qnt` | Pinned interleavings for `serve.qnt` (`serve_test`, `served_test`) |
| `check.sh` | Runs every check below and compares each result with the expected one |

## Server rules covered

- **`serve.lock` / `server.lock`** (SPEC-CONCURRENCY §2 table, §3.1):
  every live server, `kit serve` and any layout server, holds
  `serve.lock` shared; a layout server also holds `server.lock` exclusively.
  Modelled in `serveLocks` (invariants `ServeLockRW`, `OneKitServer`,
  `UpServersHoldServeShared`, `NoMissedDetection`).
- **Startup sweep** (§3.1, "The one exclusive hold"): a starting
  `kit serve` tries `serve.lock` exclusively without waiting, sweeps
  stale upload temp files in `packs/` only while it holds it, then drops it
  and takes the shared lock; busy means skip. Modelled against concurrent
  uploads of other servers, including a stalled streaming upload whose temp
  file is older than the age bound (`SweepAlone`, `NoLiveUploadSwept`).
- **File transport stripe locks** (SPEC-REFS §5.1.1): a single-ref write
  (`file`) takes the repo lock `<root>/.kit/refs/.lock` shared, then the
  exclusive lock of its ref's stripe. A multi-file step (`fileTx`,
  `FileTransport::with_ref_lock`) takes the repo lock exclusive and no
  stripe. `sharers` tracks the shared holders. `OneFileWriterPerRef` (two
  writes to one ref never overlap), `FileStepAlone` (an exclusive step
  excludes every file write) and the repo lock's read-write rule in
  `LockOwnership` are Safety conjuncts; `WitnessStripesOverlap` shows that
  writes to refs in different stripes do overlap, and the `refs2_collide`
  instance (both refs in one stripe) shows that it is then unreachable.
  `WRITER_PREF` selects a repo lock that makes a new shared hold wait
  behind a waiting exclusive request, as an in-process read-write lock
  may; `false` is an OS flock, which grants it.
- **Cross-domain gap covers layout server** (§3.1): a layout server
  fs-layout deployment writes refs through `FileTransport` under the same
  locks (`FsLayoutStore::apply` -> `FileTransport::with_ref_lock`), so in
  `refs.qnt` a `file` or `fileTx` op is a CAS from `kit serve`, a layout
  server or a `kit+file://` push alike. The
  `WitnessCrossDomainGap` witness is still reachable, as documented.
- **Served names, SPEC-REFS v3 §2**, and the **512-byte bound, §3**:
  `servedNames` checks that a server refuses a name outside `refs/`, or
  one over the bound, on ReadRef / UpdateRef / both AdvanceRefs names,
  **before touching storage**, with an explicit error, never as absent;
  that a refused request writes nothing (no partial AdvanceRefs); and that
  a listing skips stored stray refs (`<root>/main`, over-long names)
  (`RefuseBeforeStorage`, `ExplicitRefusal`, `RefusedWritesNothing`,
  `ListingServedOnly`). Names are abstract classes (served, outside
  `refs/`, over-long, grammar-invalid). **Which byte strings fall in which
  class is pure grammar, left to unit tests and conformance vectors**
  (`kit_core::refs` tests; the `kit-serve` ssh tests), as are the derived local bounds (495 / 502 bytes) and
  prefix normalization (§4.2).
- **Memory transport**: `kit-transport-memory`'s `update_ref` holds its
  `Mutex` across read-check-write, and SPEC-REFS §5.1 says `atomic*`
  (in-process only). The Safety conjunct `NoLostUpdateMem` covers the race; the race survives as the
  `refs2_memNoMutex` mutant (also caught for Missing, which a HashMap
  cannot decide by O_EXCL).

## Running

```sh
./check.sh               # quint typecheck + test + run, then TLC
TLC=0 ./check.sh         # skip TLC
APALACHE=1 ./check.sh    # add the bounded apalache-mc runs
```

Pins (verification toolchain): quint 0.32.0; Apalache 0.62.2 run
directly on the TLA+ that `quint compile --target tlaplus` produces (quint
uses its bundled Apalache only to transpile; `quint verify` is not used);
TLC is `tlc2.TLC` from the Apalache 0.62.2 jar; Java 21.

Tool locations default to `${FV_HOME:-$HOME/.local/share/kit-fv}/apalache-0.62.2/`
and can be overridden with `APALACHE_MC` and `TLA2TOOLS`; `JAVA_HOME`
defaults to `/usr/libexec/java_home -v 21`, then Homebrew's `openjdk@21`.
Memory: `TLC_HEAP` (default 4g), `TLC_WORKERS` (2), `APALACHE_HEAP` (4g).
Other knobs: `QUINT=0` skips `quint run`; `ONLY=<regex>` restricts TLC and
Apalache to matching `<module>::<invariant>` checks; `STEPS` (quint run depth, 40), `SAMPLES` (20000),
`REFS_DEPTH` (Apalache length for refs2 Safety, 8), `SERVE_DEPTH` (12).

Each line of output is `<check>  <expected> (as expected)` or
`UNEXPECTED: ...`; the script exits 1 on any unexpected outcome. `ok` means
the invariant holds within the stated bound; `violation` means the checker
reached a mutant, canary or documented-gap witness, as it must.

## Checks and bounds

Bounded is not proved. Nothing here is a proof for unbounded processes,
refs or values.

| Checker | Instance | Bound | Result |
|---------|----------|-------|--------|
| `quint test` | `refs_test` (29 runs), `refs_wpref_test` (2), `refs_collide_test` (1), `serve_test` (13), `served_test` (7) | pinned traces | all pass |
| `quint run` | `refs3`, `refs2` Safety | 20000 samples x 40 steps, seed 0x1 (the stripe-lock model was last run at 2000 samples: one 20000-sample run takes about 20 minutes on a 4-CPU machine) | ok |
| `quint run` | `serve2`, `serve3`, `served` Safety | same | ok |
| TLC | `serve2` Safety | exhaustive: 2 server slots (each may start as either binary), 1 local command, 3 uploaders | ok, 18,812 states |
| TLC | `serve3` Safety | exhaustive: 3 server slots | ok, 152,012 states |
| TLC | `served` Safety | exhaustive (one request at a time, 5 name classes, stray files present or not) | ok, 66,064 states |
| TLC | `refs2` Safety, slice `domains` | exhaustive for 2 processes whose ops are local `updateRef`, `file` or `mem` on one ref (TLC `CONSTANT KINDS <- ...`, `REFS <- {0}`), CONSTRAINT `nextEntry <= 2`; VIEW drops only `lastAction` | ok, 3,770,793 states |
| TLC | `refs2` Safety, slice `chain` | same, ops `commit`, `amend`, `branch`, `checkout`, `gc` on one ref | ok, 3,538,512 states |
| TLC | `refs2` Safety, slice `file` | same, ops `file` and `fileTx` on both refs | ok, 308,475 states |
| TLC | `refs2_collide` Safety and `WitnessStripesOverlap`, slice `file` | same, both refs in one stripe | ok, 277,371 states (the witness is unreachable) |
| TLC | `refs3_wpref` Safety, slice `file3` | 3 processes, ops `file` and `fileTx` on one ref, writer-preferring repo lock | ok, 2,198,691 states |
| TLC | `refs3_stripeFirstFlock` `NoDeadlock`, slice `file3` | same, flock repo lock, single-ref writes may take the stripe first | ok, 7,902,603 states: with a flock repo lock the opposite order does not deadlock |
| Apalache 0.62.2 | `refs2` Safety (full op space) | length `REFS_DEPTH` = 8 (~22 min under load) | ok for the model before the stripe locks; not rerun since |
| Apalache 0.62.2 | `serve2` Safety, `served` Safety | length 12 / 8 | ok |

Every mutant and witness in the table below was reached by TLC and/or
Apalache as well as by its pinned `quint test` scenario (TLC state counts
to the counterexample: 53 to 2,422,421; Apalache lengths 2 to 9, the
shortest traces that can exhibit each).

Mutants and witnesses (each must be reached; `check.sh` lists every one):

| Instance | Must violate | What it shows |
|----------|--------------|---------------|
| `refs3_misorder` | `NoDeadlock`, `LockOrderRespected` | the §4 order is what prevents deadlock |
| `refs2_noRefLock` | `NoLostUpdateLocal` | pre-fix lost update |
| `refs2_noFileLock` | `NoLostUpdateFile` | RefLock is needed |
| `refs2_gcSkipTrees` | `ExpireHoldsSuperset`, `NoRecordExpireInterleave` | §3.2 superset rule |
| `refs2_racyAcquire` | `LockOwnership` | broken flock |
| `refs2_memNoMutex` | `NoLostUpdateMem` | the v1 "NOT atomic" memory row |
| `refs2_noStripeLock` | `OneFileWriterPerRef`, `NoLostUpdateFile` | a single-ref write needs its stripe lock; the shared repo lock excludes nothing |
| `refs2_txShared` | `FileStepAlone` | a multi-file step needs the repo lock exclusive |
| `refs3_stripeFirst` | `NoDeadlock` (writer-preferring repo lock), `LockOrderRespected` | the order repo lock, then stripe lock, prevents a deadlock between a write in order, a write out of order and a waiting multi-file step |
| `refs2` | `WitnessStripesOverlap` | writes to refs in different stripes overlap; `refs2_collide` shows it unreachable with one stripe |
| `refs3` | `WitnessCrossDomainGap` | documented §3.1 gap (local vs `kit serve` or a layout server, when the served root is the common dir) |
| `serve2_sweepUnlocked` | `SweepAlone`, `NoLiveUploadSwept` | the sweep needs the exclusive hold |
| `serve2_sweepUnderShared` | `SweepAlone`, `NoLiveUploadSwept` | a shared hold does not exclude other servers' uploads |
| `serve2_serverSkipsServe` | `UpServersHoldServeShared`, `NoMissedDetection`, `NoLiveUploadSwept` | a layout server must hold `serve.lock` |
| `serve2_serverLockShared` | `OneKitServer` | `server.lock` must be exclusive |
| `serve2_ftSlow` | `NoLiveUploadSwept` | ASSUMPTION: lockless `kit+file://` uploads rely on the 1 h age bound |
| `serve2` | `WitnessUndetectedLateServer` | documented §3.1 gap: detection is one-directional |
| `served_checkAfterRead` | `RefuseBeforeStorage`, `ExplicitRefusal` | pre-v3 behaviour (answering `main` from storage / as absent) |
| `served_headCheckedLate` | `RefuseBeforeStorage`, `RefusedWritesNothing` | both AdvanceRefs names must be checked before the first write |
| `served_listNoSkip` | `ListingServedOnly` | stray refs must be skipped in listings |

Canaries (`Canary*`, `Witness*` reachability) confirm the interesting
states are visited: a sweep removes a crashed upload's file, a start skips
its sweep, `kit serve` and a layout server share a root, a `kit serve`
starts during a stalled upload, refusals of each kind are reached, and a
served AdvanceRefs succeeds.

The unsliced `refs2` space (8 kinds, 2 trees, 2 refs, 4 conditions, 2
values, 2 processes) passed 1.5 M distinct states at BFS depth 4 in 2
minutes with the queue still growing, so it does not fit the 30-minute /
4 GB budget: TLC covers it by the two slices above, quint run and Apalache
cover the whole space to their bounds.

## Abstractions

- Time is two ages, fresh and stale (older than `STALE_UPLOAD_AGE`, 1 h).
  A server's streaming upload can stall and go stale while live; only the
  lock protects it. A `FileTransport` upload is one `write_atomic` call and
  is assumed never stale while live (the age-bound assumption in the
  `lock_and_sweep` comment); `serve2_ftSlow` drops it.
- The probe's momentary exclusive hold is one atomic step; its other
  effects (a starting `kit serve` skips its sweep, a starting server waits)
  are liveness only. Lock waits never time out (the 5 s timeout is
  abstracted, as in `refs.qnt`). Stop and crash are one action.
- The 256 stripes are two: ref 0 and ref 1 each have one (ids 10 and
  11), or share id 10 under `COLLIDE`. The stripe mapping itself (the first
  byte of the BLAKE3 digest of the ref name) is pure arithmetic, left to the
  `kit-transport-file` unit tests. So is the clash between a ref and a ref
  below it (`refs/heads/a`, `refs/heads/a/b`) under different stripe locks:
  the model's refs are not nested.
- Each file-transport instance's in-process locks mirror its OS locks and
  are not modelled apart from them; `WRITER_PREF` covers the in-process
  read-write lock's possible writer preference.
- A SQLite-metadata layout server deployment keeps refs in SQLite (the root marker makes
  `FileTransport` refuse ref writes on that root) and is not modelled;
  neither is a layout server's S3 spool sweep (under `server.lock`, used
  only by a layout server).
- The git bridge locks (`git-<remote>.lock`, `git-import-key.lock`) that
  another track is adding to SPEC-CONCURRENCY §2/§4 are not in this model.

## Model-based conformance (ref conformance model)

`refs_mbt.qnt` (additive; `refs.qnt` is unchanged) instantiates `refs.qnt`
with `NO_FAULTS` for 2 (`refs_mbt2`) and 3 (`refs_mbt3`) processes and adds
the scheduler `stepLin`: a disk `readRef` is not scheduled while a process
of the other disk lock domain (local chain vs file transport) has read the
same ref and not committed. That removes exactly the documented §3.1
cross-domain gap, which the real, atomic API calls cannot reproduce, so every
trace is linearizable at the ref level and can be replayed. Generated traces
must satisfy `LinSafety` (`Safety` and `NoCrossDomainGap`); the
unrestricted `stepAll` must still reach the gap.

`formal/scripts/gen-refs-traces.sh` draws the ITF traces
(`quint run --mbt --out-itf`, one seed each, 60 steps), strips the
variables the harness does not read, and writes them to
`rust/crates/kit-formal-conformance/tests/fixtures/formal_refs/`
(`CHECK=1` regenerates into a temp dir and diffs). The Rust test
`rust/crates/kit-formal-conformance/tests/formal_refs_conformance.rs`
(`cargo test -p kit-formal-conformance`, offline, normal CI) replays each
step against `kit_core::refs`, `ops::recovery`, `FileTransport` and
`MemoryTransport` on a temp repo and compares, after every step, the disk
refs (through `refs::read_ref` and through `FileTransport`), the memory
refs, the recovery log, and every commit's outcome (`ok` / `conflict` /
`notfound`). The op-to-call mapping and what is not compared (lock steps,
the `history-mmr` ancestry path) are in that file's header.

| Check | Bound | Result |
|-------|-------|--------|
| `quint run refs_mbt2 --step stepLin` `LinSafety` | 2000 samples x 60 steps, seed 0x1 | ok |
| `quint run refs_mbt3 --step stepLin` `LinSafety` | 2000 samples x 60 steps, seed 0x1 | ok |
| `quint run refs_mbt3 --step stepLin` `LinSafety` (one-off, not in the script) | 20000 samples x 40 steps, seed 0x1, 9 min | ok |
| `quint run refs_mbt3 --step stepAll` `NoCrossDomainGap` | 20000 samples x 60 steps, seed 0x1 | violation (as it must) |
| Replay of 5 fixtures (`refs_mbt2` seeds 0x1, 0x9, 0xc, 0x18, 0x1a) | 300 steps, 43 commits, the multi-file step `fileTx` included | every step agrees |
| `harness_detects_adapter_faults` | 5 deliberate adapter bugs (one per domain, plus conditional delete and dropped record) | each caught |
| `harness_detects_a_tampered_trace` | flipped outcome, altered ref value | each caught at that state |

Bounded is not proved: the fixtures are 5 sampled traces, not every
interleaving.
