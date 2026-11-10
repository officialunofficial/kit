// -*- mode: Bluespec; -*-
// Repository cursor model for the file transport (SPEC-TRANSPORT §1.2,
// SPEC-REFS §5.1.2).
//
// The cursor digests the stripe counts and the modification time of every
// ref directory. A writer that counts (the file transport) bumps a count
// and, by its rename, a directory time. A writer that does not count (kit
// 0.7.3 and earlier) changes only the directory time. Both write under a
// lock that excludes a cursor read, so a write is one step here.
//
// A file system stamps a time at a coarse grain, so two writes in one grain
// leave one time. The transport offers no cursor while any directory time is
// at most WINDOW old, or ahead of the clock. It checks the times before it
// reads a count, so a withheld read reads none and has no effect here.
//
// The client remembers one cursor with the number of writes completed when
// it read it (`kept`). `stale` records a read whose cursor equals the kept
// one although a write completed in between: the stale skip the cursor must
// never allow. The clock never goes back; clock skew between machines is not
// modelled.
module cursorModel {
  type Faults = {
    noGuard: bool,    // a cursor is offered however fresh a directory time is
    noStamps: bool,   // the cursor digests the counts only
  }

  const DIRS: Set[str]
  const GRAIN: int    // file-system time granularity, in clock ticks
  const WINDOW: int   // a time this old or newer is not trusted
  const MAXT: int     // clock bound
  const MAXW: int     // write bound
  const FAULTS: Faults

  type Cursor = { count: int, stamps: str -> int }

  var clock: int
  var stamp: str -> int
  var count: int
  var writes: int            // ghost: completed ref writes
  var kept: { has: bool, c: Cursor, writes: int }
  var stale: bool
  var offered: int           // non-vacuity: cursors offered so far
  var equalSeen: bool        // non-vacuity: an equal cursor was confirmed

  pure def coarse(t: int, grain: int): int = (t / grain) * grain

  val fresh: bool = DIRS.exists(d => stamp.get(d) >= clock - WINDOW)

  val current: Cursor = {
    count: count,
    stamps: if (FAULTS.noStamps) DIRS.mapBy(d => 0) else stamp,
  }

  action init = all {
    clock' = WINDOW + 1,
    stamp' = DIRS.mapBy(d => 0),
    count' = 0,
    writes' = 0,
    kept' = { has: false, c: { count: 0, stamps: DIRS.mapBy(d => 0) }, writes: 0 },
    stale' = false,
    offered' = 0,
    equalSeen' = false,
  }

  action unchangedRest = all {
    kept' = kept, stale' = stale, offered' = offered, equalSeen' = equalSeen,
  }

  action tick = all {
    clock < MAXT,
    clock' = clock + 1,
    stamp' = stamp, count' = count, writes' = writes,
    unchangedRest,
  }

  // A write by a writer that counts (`counts`) or one that does not.
  action write(d: str, counts: bool): bool = all {
    writes < MAXW,
    stamp' = stamp.set(d, coarse(clock, GRAIN)),
    count' = if (counts) count + 1 else count,
    writes' = writes + 1,
    clock' = clock,
    unchangedRest,
  }

  // The cursor read now equals the kept one.
  val same: bool = kept.has and kept.c == current

  // A cursor read; the client may keep it.
  action read(keep: bool): bool = all {
    FAULTS.noGuard or not(fresh),
    stale' = (stale or (same and kept.writes != writes)),
    equalSeen' = (equalSeen or (same and kept.writes == writes)),
    kept' = if (keep) { has: true, c: current, writes: writes } else kept,
    offered' = if (offered < 3) offered + 1 else offered,
    clock' = clock, stamp' = stamp, count' = count, writes' = writes,
  }

  action step = any {
    tick,
    nondet d = DIRS.oneOf()
    nondet counts = Set(true, false).oneOf()
    write(d, counts),
    nondet keep = Set(true, false).oneOf()
    read(keep),
  }

  // ---- invariants
  // An equal cursor never hides a completed write.
  val NoStaleSkip: bool = not(stale)
  val Safety: bool = NoStaleSkip

  // ---- non-vacuity canaries (each must be violated)
  val CanaryNoCursorOffered: bool = offered < 2
  val CanaryNoEqualCursor: bool = not(equalSeen)

  // ---- TLC/Apalache entry points
  action q_init = init
  action q_step = step
  val q_inv = Safety
}

module cursor2 {          // 2 directories, a coarse grain, the shipped window
  import cursorModel(DIRS = Set("heads", "packmap"), GRAIN = 3, WINDOW = 3, MAXT = 12, MAXW = 4,
    FAULTS = { noGuard: false, noStamps: false }).*
}
module cursor2_noGuard {  // NoStaleSkip
  import cursorModel(DIRS = Set("heads", "packmap"), GRAIN = 3, WINDOW = 3, MAXT = 12, MAXW = 4,
    FAULTS = { noGuard: true, noStamps: false }).*
}
module cursor2_noStamps { // NoStaleSkip
  import cursorModel(DIRS = Set("heads", "packmap"), GRAIN = 3, WINDOW = 3, MAXT = 12, MAXW = 4,
    FAULTS = { noGuard: false, noStamps: true }).*
}
module cursor2_shortWindow { // NoStaleSkip: a window shorter than the grain
  import cursorModel(DIRS = Set("heads", "packmap"), GRAIN = 3, WINDOW = 1, MAXT = 12, MAXW = 4,
    FAULTS = { noGuard: false, noStamps: false }).*
}
