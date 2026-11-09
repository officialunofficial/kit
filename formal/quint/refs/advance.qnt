// -*- mode: Bluespec; -*-
// The two-ref advance of a branch head and its packmap, and the push
// driver's re-baseline gate (SPEC-REFS §5.1.1, SPEC-TRANSPORT §7).
// Companion of refs.qnt, which models the locks themselves; here the locks
// are one step that checks both conditions, as the file transport's
// `advance_refs` does under both refs' stripe locks.
//
// Module `twoRefAdvance` models:
//   - a serialized advance (the file transport): under the locks it checks
//     the head condition, writes the packmap, then, in a later step, the
//     head. A writer holds the locks across both writes, so no other
//     advance interleaves, but every state between the writes is visible to
//     a lock-free reader, and a crash there leaves it for good;
//   - an atomic advance (`atomic`): both refs in one step;
//   - the push driver: a lease push plans its pack against the head it
//     reads and conditions the head write on that head; it re-baselines
//     (resets the chain to its tip's full closure) only when the gate
//     allows it. A force push plans against the head it reads and takes the
//     guarded force driver: it re-plans when the head moved or a reset
//     since its plan dropped the chain its plan relied on (the anchor).
//
// Abstractions (explicit):
//   - Objects are commits. The closure of a commit is itself and its
//     ancestors (a fixed graph: c0 <- c1 <- c2 <- c3, c0 <- d <- e). A pack
//     planned against head h for tip t holds closure(t) minus closure(h);
//     its delta bases and the objects it leaves out lie in closure(h).
//   - The chain is the set of objects its packs hold. An append adds the
//     pack; a reset replaces the set with closure(t). The packmap version
//     counts writes; `lastReset` is the version of the last reset, so a
//     plan's anchor survives while no reset came after it.
//   - The chain depth is not modelled: whenever the gate allows a reset,
//     the push may or may not take it.
//   - A lease push conditions on the head its plan read (the driver reads
//     the remote head to plan; a stale lease fails the head check).
//   - Each process makes one push, which may re-plan; a failed lease push
//     stops. Crashing is only modelled between the two writes, the one
//     place it leaves a state no step would; a crash elsewhere changes
//     nothing or equals a finished advance.
//
// Safety: `Consistent`, in every reachable state, so for every reader and
// after every crash: the head's closure lies in the chain.
//
// Checks: ./check.sh (README.md lists each command and its expected outcome).
module twoRefAdvance {
  type Proc = str

  // Mutation switches (non-vacuity only) and the transport kind.
  type Faults = {
    atomic: bool,       // the transport's advance is atomic, not serialized
    noAncestry: bool,   // MUTANT: a serialized advance resets any lease push
    forceOrdered: bool, // MUTANT: force pushes append on the ordered path, no anchor check
  }

  const PROCS: Set[Proc]
  const FAULTS: Faults

  pure val NONE: str = ""
  pure val COMMITS: Set[str] = Set("c0", "c1", "c2", "c3", "d", "e")
  pure val CLOSURE: str -> Set[str] = Map(
    "c0" -> Set("c0"),
    "c1" -> Set("c0", "c1"),
    "c2" -> Set("c0", "c1", "c2"),
    "c3" -> Set("c0", "c1", "c2", "c3"),
    "d" -> Set("c0", "d"),
    "e" -> Set("c0", "d", "e"),
  )
  pure def ancestor(a: str, t: str): bool = CLOSURE.get(t).contains(a)

  // --------------------------------------------------------------- state
  var brHead: str             // the branch head
  var objs: Set[str]          // the objects the packmap chain holds
  var pmv: int                // packmap version (writes so far)
  var lastReset: int          // version of the last reset, 0 if none
  var holder: Proc            // the writer between its two writes, NONE if none
  var pc: Proc -> str         // fresh | idle | planned | wrote | done | crashed
  var tip: Proc -> str
  var force: Proc -> bool
  var planHead: Proc -> str
  var planPm: Proc -> int
  var reset: Proc -> bool
  var replans: Set[Proc]      // force pushes that re-planned

  // The re-baseline gate for a lease push of `t` conditioned on head `h`.
  def gate(t: str, h: str): bool =
    FAULTS.atomic or FAULTS.noAncestry or ancestor(h, t)

  action init = all {
    brHead' = "c2",
    objs' = CLOSURE.get("c2"),
    pmv' = 0,
    lastReset' = 0,
    holder' = NONE,
    pc' = PROCS.mapBy(_ => "fresh"),
    tip' = PROCS.mapBy(_ => NONE),
    force' = PROCS.mapBy(_ => false),
    planHead' = PROCS.mapBy(_ => NONE),
    planPm' = PROCS.mapBy(_ => 0),
    reset' = PROCS.mapBy(_ => false),
    replans' = Set(),
  }

  action choose(p: Proc): bool = {
    nondet t = COMMITS.oneOf()
    nondet f = Set(false, true).oneOf()
    all {
      pc.get(p) == "fresh",
      pc' = pc.set(p, "idle"),
      tip' = tip.set(p, t),
      force' = force.set(p, f),
      brHead' = brHead, objs' = objs, pmv' = pmv, lastReset' = lastReset, holder' = holder,
      planHead' = planHead, planPm' = planPm, reset' = reset, replans' = replans,
    }
  }

  // Read the head and the packmap, plan the pack, decide on a reset.
  action plan(p: Proc): bool = {
    nondet r = Set(false, true).oneOf()
    all {
      pc.get(p) == "idle",
      not(r) or (not(force.get(p)) and gate(tip.get(p), brHead)),
      pc' = pc.set(p, "planned"),
      planHead' = planHead.set(p, brHead),
      planPm' = planPm.set(p, pmv),
      reset' = reset.set(p, r),
      brHead' = brHead, objs' = objs, pmv' = pmv, lastReset' = lastReset, holder' = holder,
      tip' = tip, force' = force, replans' = replans,
    }
  }

  // The packmap write of an advance whose checks passed. An atomic
  // advance writes the head in the same step.
  action write(p: Proc): bool = {
    val t = tip.get(p)
    val v = pmv + 1
    all {
      objs' = if (reset.get(p)) CLOSURE.get(t)
              else objs.union(CLOSURE.get(t).exclude(CLOSURE.get(planHead.get(p)))),
      pmv' = v,
      lastReset' = if (reset.get(p)) v else lastReset,
      if (FAULTS.atomic) all {
        brHead' = t, holder' = NONE, pc' = pc.set(p, "done"),
      } else all {
        brHead' = brHead, holder' = p, pc' = pc.set(p, "wrote"),
      },
      tip' = tip, force' = force, planHead' = planHead, planPm' = planPm,
      reset' = reset, replans' = replans,
    }
  }

  // Move `p` to `state`; change no ref, no plan and no lock.
  action moveTo(p: Proc, state: str): bool = all {
    pc' = pc.set(p, state),
    brHead' = brHead, objs' = objs, pmv' = pmv, lastReset' = lastReset,
    tip' = tip, force' = force, planHead' = planHead, planPm' = planPm, reset' = reset,
  }

  // Take the locks and check the conditions.
  action advance(p: Proc): bool = all {
    pc.get(p) == "planned",
    holder == NONE,
    if (not(force.get(p))) {
      // A lease push: the head condition is the head its plan read.
      if (brHead == planHead.get(p)) write(p)
      else all { moveTo(p, "done"), holder' = holder, replans' = replans }
    } else if (FAULTS.forceOrdered) {
      // An unconditional head write appended to whatever chain is there.
      write(p)
    } else {
      // The guarded force driver: a moved head or a lost anchor re-plans.
      if (brHead == planHead.get(p) and lastReset <= planPm.get(p)) write(p)
      else all { moveTo(p, "idle"), holder' = holder, replans' = replans.union(Set(p)) }
    },
  }

  action writeHead(p: Proc): bool = all {
    pc.get(p) == "wrote",
    brHead' = tip.get(p),
    holder' = NONE,
    pc' = pc.set(p, "done"),
    objs' = objs, pmv' = pmv, lastReset' = lastReset,
    tip' = tip, force' = force, planHead' = planHead, planPm' = planPm,
    reset' = reset, replans' = replans,
  }

  // The process dies between the two writes; the kernel drops its locks.
  action crash(p: Proc): bool = all {
    pc.get(p) == "wrote",
    moveTo(p, "crashed"),
    holder' = NONE,
    replans' = replans,
  }

  action step = {
    nondet p = PROCS.oneOf()
    any { choose(p), plan(p), advance(p), writeHead(p), crash(p) }
  }

  // --------------------------------------------------------------- safety
  val Consistent: bool = CLOSURE.get(brHead).subseteq(objs)
  val Safety: bool = Consistent

  // ------------------------------------------- canaries (must be violated)
  val CanaryNoReset: bool = lastReset == 0
  val CanaryNoCrashAfterReset: bool =
    not(lastReset > 0 and PROCS.exists(p => pc.get(p) == "crashed"))
  val CanaryNoForceReplan: bool = replans == Set()
}

// ------------------------------------------------------------ instances
// Faults literal: { atomic, noAncestry, forceOrdered }.
module advance3 {               // the file transport: serialized advance
  import twoRefAdvance(PROCS = Set("p1", "p2", "p3"),
    FAULTS = { atomic: false, noAncestry: false, forceOrdered: false }).*
}
module advance3_atomic {        // an atomic advance resets any lease push
  import twoRefAdvance(PROCS = Set("p1", "p2", "p3"),
    FAULTS = { atomic: true, noAncestry: false, forceOrdered: false }).*
}
module advance3_noAncestry {    // Consistent
  import twoRefAdvance(PROCS = Set("p1", "p2", "p3"),
    FAULTS = { atomic: false, noAncestry: true, forceOrdered: false }).*
}
module advance3_forceOrdered {  // Consistent
  import twoRefAdvance(PROCS = Set("p1", "p2", "p3"),
    FAULTS = { atomic: false, noAncestry: false, forceOrdered: true }).*
}
module advance3_atomicForceOrdered {  // Consistent: an atomic advance needs the driver too
  import twoRefAdvance(PROCS = Set("p1", "p2", "p3"),
    FAULTS = { atomic: true, noAncestry: false, forceOrdered: true }).*
}
