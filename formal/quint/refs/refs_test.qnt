// -*- mode: Bluespec; -*-
// Deterministic scenarios for refs.qnt: each run pins one interleaving and
// checks the expected outcome. Scenarios marked MUTANT / WITNESS demonstrate
// that the corresponding invariant in refs.qnt can fail (non-vacuity) or that
// a documented gap is reachable.
module refs_test {
  import refs(PROCS = Set("p1", "p2", "p3"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false, memNoMutex: false, noStripeLock: false, stripeFirst: false, txShared: false },
              COLLIDE = false, WRITER_PREF = false, NESTED = false, CLASH_UNCHECKED = false).* from "./refs"

  pure def op(kind: str, t: int, r: int, c: Cond, v: int, d: bool): Op =
    { kind: kind, tree: t, ref: r, cond: c, value: v, del: d }

  pure val SAFE_INIT = NO_FAULTS

  action beginOp(p: Proc, o: Op): bool = begin(p, o, false)

  // Two local conditional writers from DIFFERENT worktrees (no shared
  // worktree.lock) race Match(1) -> 2 on refs/heads/a. refs-<ref>.lock
  // blocks the second; it then observes 2 and conflicts (SPEC-REFS §5.1,
  // test vector 5 exactly-one-winner).
  run localMatchExactlyOneWinnerTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("commit", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("updateRef", 1, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .then(acquire("p2"))
      .expect(not(canMove("p2")))            // blocked on refs-<a>.lock
      .then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == 2, lastAction.outcome == "conflict" })

  // Rename's delete_ref_if_matches vs a concurrent Match advance.
  run renameDeleteVsCommitTest =
    initFixed(SAFE_INIT, 1, ABSENT, ABSENT)
      .then(beginOp("p1", op("branch", 0, 0, Match(1), 1, true)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .then(beginOp("p2", op("commit", 0, 0, Match(1), 2, false)))
      .then(acquire("p2"))
      .expect(not(canMove("p2")))            // history lock held by p1
      .then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == ABSENT, lastAction.outcome == "conflict" })

  // An unconditional (Any) write cannot slip into a Match critical section.
  run anyWaitsForMatchTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(readRef("p1"))
      .then(beginOp("p2", op("updateRef", 1, 0, Any, 1, false)))
      .then(acquire("p2"))
      .expect(not(canMove("p2")))
      .then(commitRef("p1"))
      .expect(and { Safety, disk.get(0) == 2 })

  // Missing is decided by O_EXCL on the actual file: at most one winner even
  // WITHOUT the ref lock (SPEC-REFS §8 ".missing succeeds at most once").
  run missingAtomicEvenWithoutLockTest =
    initFixed({ ...NO_FAULTS, noRefLock: true }, ABSENT, ABSENT, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Missing, 1, false)))
      .then(beginOp("p2", op("updateRef", 1, 0, Missing, 2, false)))
      .then(acquire("p1")).then(acquire("p2"))
      .then(readRef("p1")).then(readRef("p2"))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == 1, lastAction.outcome == "conflict" })

  // MUTANT (pre-fix): no refs-<ref>.lock -> Match lost update; NoLostUpdateLocal fails.
  run mutantNoRefLockLostUpdateTest =
    initFixed({ ...NO_FAULTS, noRefLock: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("updateRef", 1, 0, Match(1), 1, false)))
      .then(acquire("p1")).then(acquire("p2"))
      .then(readRef("p1")).then(readRef("p2"))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(and { not(NoLostUpdateLocal), lastAction.outcome == "ok" })

  // File transport: the stripe lock serialises two Match CAS on one ref of
  // the same root. Both hold the repo lock shared.
  run fileMatchSerialisedTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("file", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("file", 0, 0, Match(1), 1, false)))
      .then(acquire("p1")).then(acquire("p1"))
      .then(acquire("p2"))
      .expect(not(canMove("p2")))
      .then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == 2, lastAction.outcome == "conflict" })

  // MUTANT: file transport without RefLock -> NoLostUpdateFile fails.
  run mutantNoFileLockTest =
    initFixed({ ...NO_FAULTS, noFileLock: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("file", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("file", 0, 0, Match(1), 1, false)))
      .then(readRef("p1")).then(readRef("p2"))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(not(NoLostUpdateFile))

  // Memory transport: `update_ref` holds its Mutex across read-check-write
  // (kit-transport-memory), so two Match(1) CAS have exactly one winner.
  run memMatchAtomicTest =
    initFixed(SAFE_INIT, ABSENT, ABSENT, 1)
      .then(beginOp("p1", op("mem", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("mem", 0, 0, Match(1), 1, false)))
      .then(acquire("p1"))
      .expect(not(canMove("p2")))            // blocked on the Mutex
      .then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, mem.get(0) == 2, lastAction.outcome == "conflict" })

  // MUTANT (the old SPEC-REFS §5.1 memory row, "NOT atomic"): without the
  // Mutex both Match(1) CAS succeed and one write is lost.
  run mutantMemNoMutexTest =
    initFixed({ ...NO_FAULTS, memNoMutex: true }, ABSENT, ABSENT, 1)
      .then(beginOp("p1", op("mem", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("mem", 0, 0, Match(1), 1, false)))
      .then(readRef("p1")).then(readRef("p2"))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(and { not(NoLostUpdateMem), not(Safety), lastAction.outcome == "ok" })

  // MUTANT: without the Mutex even Missing races (a HashMap has no O_EXCL).
  run mutantMemNoMutexMissingTest =
    initFixed({ ...NO_FAULTS, memNoMutex: true }, ABSENT, ABSENT, ABSENT)
      .then(beginOp("p1", op("mem", 0, 0, Missing, 2, false)))
      .then(beginOp("p2", op("mem", 0, 0, Missing, 1, false)))
      .then(readRef("p1")).then(readRef("p2"))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(and { not(NoLostUpdateMem), mem.get(0) == 1 })

  // File transport stripe locks (SPEC-REFS §5.1.1). A single-ref write
  // holds the repo lock shared, then its stripe lock: two writes to refs in
  // different stripes overlap.
  run fileStripesOverlapTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("file", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("file", 0, 1, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1"))
      .then(acquire("p2")).then(acquire("p2"))
      .then(readRef("p1")).then(readRef("p2"))
      .expect(and { Safety, not(WitnessStripesOverlap) })
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == 2, disk.get(1) == 2 })

  // A step that holds the repo lock exclusive (`with_ref_lock`) waits for
  // a single-ref write that holds it shared, and excludes later ones.
  run fileStepExcludesWritesTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("file", 0, 0, Match(1), 2, false)))
      .then(acquire("p1"))
      .then(beginOp("p2", op("fileTx", 0, 1, Match(1), 2, false)))
      .expect(not(canMove("p2")))            // p1 holds the repo lock shared
      .then(acquire("p1")).then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2"))
      .then(beginOp("p3", op("file", 0, 0, Match(2), 1, false)))
      .expect(not(canMove("p3")))            // p2 holds it exclusive
      .then(readRef("p2")).then(commitRef("p2")).then(release("p2"))
      .then(acquire("p3")).then(acquire("p3")).then(readRef("p3")).then(commitRef("p3"))
      .expect(and { Safety, disk.get(0) == 1, disk.get(1) == 2 })

  // Two writes to one ref serialize on its stripe lock.
  run fileSameRefSerialisesTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("file", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("file", 0, 0, Match(1), 1, false)))
      .then(acquire("p1")).then(acquire("p1"))
      .then(acquire("p2"))
      .expect(not(canMove("p2")))            // the stripe of ref 0
      .then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == 2, lastAction.outcome == "conflict" })

  // MUTANT: a single-ref write without its stripe lock. The shared repo
  // lock excludes nothing, so two writes to one ref race.
  run mutantNoStripeLockTest =
    initFixed({ ...NO_FAULTS, noStripeLock: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("file", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("file", 0, 0, Match(1), 1, false)))
      .then(acquire("p1")).then(acquire("p2"))
      .then(readRef("p1")).then(readRef("p2"))
      .expect(not(OneFileWriterPerRef))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(not(NoLostUpdateFile))

  // MUTANT: a multi-file step that takes the repo lock shared. A write to
  // another ref slips inside the step.
  run mutantStepTakesSharedTest =
    initFixed({ ...NO_FAULTS, txShared: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("fileTx", 0, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(readRef("p1"))
      .then(beginOp("p2", op("file", 0, 1, Match(1), 2, false)))
      .then(acquire("p2")).then(acquire("p2")).then(readRef("p2"))
      .expect(not(FileStepAlone))

  // A writer that takes its stripe lock before the repo lock does not
  // deadlock against a flock-style repo lock, which grants a shared hold
  // while an exclusive request waits. See refs_wpref_test for a repo lock
  // that does not.
  run stripeFirstFlockNoDeadlockTest =
    initFixed({ ...NO_FAULTS, stripeFirst: true }, 1, 1, ABSENT)
      .then(beginOp("p2", op("file", 0, 0, Match(1), 2, false)))
      .then(acquire("p2"))                   // p2: repo lock shared
      .then(begin("p1", op("file", 0, 0, Match(1), 1, false), true))
      .then(acquire("p1"))                   // p1: stripe of ref 0 first
      .then(beginOp("p3", op("fileTx", 0, 1, Match(1), 2, false)))
      .expect(and { not(canMove("p3")), not(canMove("p2")), canMove("p1"), NoDeadlock })

  // WITNESS — DOCUMENTED GAP (SPEC-CONCURRENCY §3.1): a local Match write
  // under refs-<ref>.lock and a file-transport write under its stripe lock (from
  // `kit serve`, a layout server or a kit+file:// push) hit the
  // same file with no common lock. Safety (per-domain) still holds.
  run crossDomainGapWitnessTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("commit", 0, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .then(readRef("p1"))
      .then(beginOp("p2", op("file", 0, 0, Match(1), 2, false)))
      .then(acquire("p2")).then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .then(commitRef("p1"))
      .expect(and { Safety, not(WitnessCrossDomainGap), lastAction.outcome == "ok" })

  // Under §4 order a reversed plan is not even startable.
  run reversedPlanRejectedTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(begin("p1", op("gc", 0, 0, Any, 1, false), true).fail())

  // MUTANT: gc taking its worktree locks in reverse -> deadlock with a
  // canonical gc (SPEC-CONCURRENCY §4). NoDeadlock and LockOrderRespected fail.
  run mutantMisorderDeadlockTest =
    initFixed({ ...NO_FAULTS, misorder: true }, 1, 1, ABSENT)
      .then(begin("p1", op("gc", 0, 0, Any, 1, false), false))
      .then(begin("p2", op("gc", 0, 0, Any, 1, false), true))
      .then(acquire("p1"))                  // p1: worktrees.lock
      .then(acquire("p2")).then(acquire("p2")) // p2: worktree.lock(1), worktree.lock(0)
      .expect(not(canMove("p1")))
      .expect(not(canMove("p2")))
      .expect(and { not(NoDeadlock), not(LockOrderRespected) })

  // MUTANT: commit taking refs-<ref> before worktree.lock (in-chain reversal).
  run mutantCommitMisorderDeadlockTest =
    initFixed({ ...NO_FAULTS, misorder: true }, 1, 1, ABSENT)
      .then(begin("p1", op("commit", 0, 0, Match(1), 2, false), false))
      .then(begin("p2", op("commit", 0, 0, Match(1), 2, false), true))
      .then(acquire("p1"))                        // p1: worktree.lock(0)
      .then(acquire("p2")).then(acquire("p2"))    // p2: refs-a, history-a
      .expect(not(NoDeadlock))

  // MUTANT: a pure 3-cycle (no 2-cycle) — exercises the 3-cycle clause of
  // NoDeadlock. p1 holds wt(main) wants refs-a; p2 (reversed) holds refs-a
  // wants wt(1); p3 (reversed gc) holds wt(1) wants wt(main).
  run mutantThreeCycleDeadlockTest =
    initFixed({ ...NO_FAULTS, misorder: true }, 1, 1, ABSENT)
      .then(begin("p1", op("updateRef", 0, 0, Match(1), 2, false), false))
      .then(begin("p2", op("updateRef", 1, 0, Match(1), 2, false), true))
      .then(begin("p3", op("gc", 0, 0, Any, 1, false), true))
      .then(acquire("p1")).then(acquire("p2")).then(acquire("p3"))
      .expect(and {
        not(NoDeadlock),
        not(PROCS.exists(a => PROCS.exists(b => waitsFor(a, b) and waitsFor(b, a)))),
        not(canMove("p1")), not(canMove("p2")), not(canMove("p3")),
      })

  // §3.2: while gc holds every worktree.lock, a producer cannot record.
  run gcExcludesRecordTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("gc", 0, 0, Any, 1, false)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .then(expireRead("p1"))
      .then(beginOp("p2", op("amend", 1, 0, Match(1), 2, false)))
      .expect(not(canMove("p2")))
      .then(expireWrite("p1")).then(release("p1"))
      .then(acquire("p2")).then(record("p2")).then(acquire("p2")).then(acquire("p2"))
      .expect(and { Safety, recLog == Set(1) })

  // MUTANT: gc expiring under worktrees.lock only -> record interleaves and
  // the entry is lost. NoRecordExpireInterleave and ExpireHoldsSuperset fail.
  run mutantGcSkipTreesTest =
    initFixed({ ...NO_FAULTS, gcSkipTrees: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("gc", 0, 0, Any, 1, false)))
      .then(acquire("p1")).then(expireRead("p1"))
      .then(beginOp("p2", op("amend", 1, 0, Match(1), 2, false)))
      .then(acquire("p2")).then(record("p2")).then(acquire("p2")).then(acquire("p2"))
      .expect(not(ExpireHoldsSuperset))
      .then(expireWrite("p1"))
      .expect(and { not(NoRecordExpireInterleave), lostRecords == Set(1) })

  // SPEC-REFS §5.1 mixed-mutation contract: an unconditional delete
  // (branch -d, delete_ref) waits for a Match in flight on the same ref.
  run deleteWaitsForMatchTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(readRef("p1"))
      .then(beginOp("p2", op("branch", 0, 0, Any, 1, true)))
      .then(acquire("p2")).then(acquire("p2"))
      .expect(not(canMove("p2")))            // blocked on refs-<a>.lock
      .then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == ABSENT, lastAction.outcome == "ok" })

  // MUTANT (pre-fix): the same unconditional delete lands inside the Match
  // window; the Match then resurrects the deleted ref. NoLostUpdateLocal fails.
  run mutantNoRefLockDeleteTest =
    initFixed({ ...NO_FAULTS, noRefLock: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(readRef("p1"))
      .then(beginOp("p2", op("branch", 0, 0, Any, 1, true)))
      .then(acquire("p2")).then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .then(commitRef("p1"))
      .expect(and { not(NoLostUpdateLocal), disk.get(0) == 2 })

  // MUTANT: a broken (non-exclusive) kernel lock lets two processes hold
  // worktree.lock(main) at once. LockOwnership fails.
  run mutantRacyAcquireTest =
    initFixed({ ...NO_FAULTS, racyAcquire: true, memNoMutex: false }, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Any, 2, false)))
      .then(beginOp("p2", op("updateRef", 0, 1, Any, 2, false)))
      .then(acquire("p1")).then(acquire("p2"))
      .expect(not(LockOwnership))

  // amend records under its worktree.lock alone (commit.rs: "Record it
  // BEFORE moving the branch (under the worktree lock)"), before it takes the
  // history and ref locks — so a record can land while another process holds
  // those, and gc's worktree.lock superset still excludes it.
  run amendRecordsBeforeRefLocksTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 1, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1"))  // wt(1), refs-a
      .then(beginOp("p2", op("amend", 0, 0, Match(1), 2, false)))
      .then(acquire("p2"))                      // wt(main)
      .expect(procs.get("p2").pc == "record")
      .then(record("p2")).then(acquire("p2"))   // history-a
      .expect(not(canMove("p2")))               // refs-a held by p1
      .expect(and { Safety, recLog == Set(1) })

  // checkout -b takes all four §4 classes in order; a gc started later
  // blocks on worktrees.lock, and one started first blocks the checkout.
  run checkoutFourLockChainTest =
    initFixed(SAFE_INIT, ABSENT, 1, ABSENT)
      .then(beginOp("p1", op("checkout", 1, 0, Missing, 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .expect(and { LockOrderRespected, owner.get(0) == "p1", owner.get(2) == "p1",
                    owner.get(3) == "p1", owner.get(5) == "p1" })
      .then(beginOp("p2", op("gc", 0, 0, Any, 1, false)))
      .expect(not(canMove("p2")))
      .then(readRef("p1")).then(commitRef("p1"))
      .expect(and { Safety, disk.get(0) == 2, lastAction.outcome == "ok" })

  // MUTANT: a reversed checkout -b (refs-a first) against a canonical commit
  // holding wt(main) and waiting for refs-a -> 2-cycle via different classes.
  run mutantCheckoutMisorderDeadlockTest =
    initFixed({ ...NO_FAULTS, misorder: true }, 1, 1, ABSENT)
      .then(begin("p1", op("commit", 0, 0, Match(1), 2, false), false))
      .then(begin("p2", op("checkout", 0, 0, Any, 2, false), true))
      .then(acquire("p1"))                        // p1: wt(main)
      .then(acquire("p2")).then(acquire("p2"))    // p2: refs-a, history-a
      .expect(and { not(NoDeadlock), not(LockOrderRespected) })
}

// Stripe scenarios that need another lock configuration.
module refs_wpref_test {
  // A repo lock that makes a new shared holder wait behind a waiting
  // exclusive request, as an in-process read-write lock may.
  import refs(PROCS = Set("p1", "p2", "p3"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false, memNoMutex: false, noStripeLock: false, stripeFirst: false, txShared: false },
              COLLIDE = false, WRITER_PREF = true, NESTED = false, CLASH_UNCHECKED = false).* from "./refs"

  pure def op(kind: str, t: int, r: int, c: Cond, v: int, d: bool): Op =
    { kind: kind, tree: t, ref: r, cond: c, value: v, del: d }

  // MUTANT: p1 takes its stripe lock before the repo lock. p2 holds the
  // repo lock shared and waits for the stripe, p3 waits for the repo lock
  // exclusive behind p2, and p1 waits for its shared hold behind p3.
  run mutantStripeFirstDeadlockTest =
    initFixed({ ...NO_FAULTS, stripeFirst: true }, 1, 1, ABSENT)
      .then(begin("p2", op("file", 0, 0, Match(1), 2, false), false))
      .then(acquire("p2"))                   // p2: repo lock shared
      .then(begin("p1", op("file", 0, 0, Match(1), 1, false), true))
      .then(acquire("p1"))                   // p1: stripe of ref 0
      .then(begin("p3", op("fileTx", 0, 1, Match(1), 2, false), false))
      .expect(and { not(canMove("p1")), not(canMove("p2")), not(canMove("p3")), not(NoDeadlock) })

  // In the documented order the same three writers finish.
  run writerPreferenceInOrderTest =
    initFixed(NO_FAULTS, 1, 1, ABSENT)
      .then(begin("p2", op("file", 0, 0, Match(1), 2, false), false))
      .then(acquire("p2"))
      .then(begin("p1", op("file", 0, 0, Match(1), 1, false), false))
      .then(begin("p3", op("fileTx", 0, 1, Match(1), 2, false), false))
      .expect(and { not(canMove("p1")), not(canMove("p3")), canMove("p2"), NoDeadlock })
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2")).then(release("p2"))
      .then(acquire("p3")).then(readRef("p3")).then(commitRef("p3")).then(release("p3"))
      .then(acquire("p1")).then(acquire("p1")).then(readRef("p1")).then(commitRef("p1"))
      .expect(and { Safety, disk.get(0) == 2, disk.get(1) == 2, lastAction.outcome == "conflict" })
}

module refs_collide_test {
  // Both refs map to one stripe.
  import refs(PROCS = Set("p1", "p2", "p3"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false, memNoMutex: false, noStripeLock: false, stripeFirst: false, txShared: false },
              COLLIDE = true, WRITER_PREF = false, NESTED = false, CLASH_UNCHECKED = false).* from "./refs"

  pure def op(kind: str, t: int, r: int, c: Cond, v: int, d: bool): Op =
    { kind: kind, tree: t, ref: r, cond: c, value: v, del: d }

  run fileStripeCollisionSerialisesTest =
    initFixed(NO_FAULTS, 1, 1, ABSENT)
      .then(begin("p1", op("file", 0, 0, Match(1), 2, false), false))
      .then(begin("p2", op("file", 0, 1, Match(1), 2, false), false))
      .then(acquire("p1")).then(acquire("p1"))
      .then(acquire("p2"))
      .expect(not(canMove("p2")))            // ref 1 shares ref 0's stripe
      .then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == 2, disk.get(1) == 2 })
}

module refs_nested_test {
  // Ref 1 is named below ref 0 (`refs/heads/a/b` below `refs/heads/a`),
  // in another stripe.
  import refs(PROCS = Set("p1", "p2", "p3"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false, memNoMutex: false, noStripeLock: false, stripeFirst: false, txShared: false },
              COLLIDE = false, WRITER_PREF = false, NESTED = true, CLASH_UNCHECKED = false).* from "./refs"

  pure def op(kind: str, t: int, r: int, c: Cond, v: int, d: bool): Op =
    { kind: kind, tree: t, ref: r, cond: c, value: v, del: d }

  // Both creates read an absent name under their own stripe, so both are
  // in their critical sections at once. The first commit wins; the second
  // reports the clash and writes nothing, and every lock is released.
  run nestedCreatesRaceTest =
    initFixed(NO_FAULTS, ABSENT, ABSENT, ABSENT)
      .then(begin("p1", op("file", 0, 0, Missing, 1, false), false))
      .then(begin("p2", op("file", 0, 1, Any, 2, false), false))
      .then(acquire("p1")).then(acquire("p1")).then(readRef("p1"))
      .then(acquire("p2")).then(acquire("p2")).then(readRef("p2"))
      .expect(not(WitnessNestedCreatesOverlap))
      .then(commitRef("p2")).then(release("p2"))
      .then(commitRef("p1"))
      .expect(and { Safety, lastAction.outcome == "clash", disk.get(0) == ABSENT, disk.get(1) == 2 })
      .then(release("p1"))
      // The root stays writable: a multi-file step and a write to the
      // winner both commit.
      .then(begin("p3", op("fileTx", 0, 1, Match(2), 1, false), false))
      .then(acquire("p3")).then(readRef("p3")).then(commitRef("p3")).then(release("p3"))
      .expect(and { Safety, disk.get(1) == 1, owner.keys().forall(l => owner.get(l) == FREE), sharers == Set() })
}

module refs_nested_unchecked_test {
  import refs(PROCS = Set("p1", "p2", "p3"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false, memNoMutex: false, noStripeLock: false, stripeFirst: false, txShared: false },
              COLLIDE = false, WRITER_PREF = false, NESTED = true, CLASH_UNCHECKED = true).* from "./refs"

  pure def op(kind: str, t: int, r: int, c: Cond, v: int, d: bool): Op =
    { kind: kind, tree: t, ref: r, cond: c, value: v, del: d }

  // MUTANT: a create that ignores the clash leaves both names behind.
  run mutantNestedPairTest =
    initFixed(NO_FAULTS, ABSENT, ABSENT, ABSENT)
      .then(begin("p1", op("file", 0, 0, Missing, 1, false), false))
      .then(begin("p2", op("file", 0, 1, Missing, 2, false), false))
      .then(acquire("p1")).then(acquire("p1")).then(readRef("p1"))
      .then(acquire("p2")).then(acquire("p2")).then(readRef("p2"))
      .then(commitRef("p2")).then(commitRef("p1"))
      .expect(not(NoNestedPair))
}
