// Copy-then-retire of one input pack (SPEC-GC "Local pack maintenance").
//
// X is a live entry of the input. Another copy of X may sit in a pair that
// stays, or in a pair that the same run retires; it may not be durable yet,
// because its publisher died before the last directory flush. E is an
// unreachable entry whose input pack is inside grace; an older pack may also
// hold it. A power loss drops a covering pair that was never flushed.
module copyRetireCore {
  const RELY_ON_RETIRED: bool  // mutant: counts a copy in a pair this run retires
  const SKIP_FLUSH: bool       // mutant: relies on a covering pair without flushing it
  const GRACE_BY_COVER: bool   // mutant: drops E inside grace because an older pack holds it

  // 0 absent, 1 present but not durable, 2 durable
  var coverState: int
  var coverRetired: bool
  var inputHas: bool
  var outHas: bool
  var eCover: bool
  var eOut: bool
  // 0 planned, 1 copied, 2 retired
  var phase: int

  action init = {
    nondet state = oneOf(Set(0, 1, 2))
    nondet retired = oneOf(Set(true, false))
    nondet older = oneOf(Set(true, false))
    all {
      coverState' = state,
      coverRetired' = retired,
      inputHas' = true,
      outHas' = false,
      eCover' = older,
      eOut' = false,
      phase' = 0,
    }
  }

  val counts = coverState > 0 and (RELY_ON_RETIRED or not(coverRetired))

  action copy = all {
    phase == 0,
    outHas' = not(counts),
    eOut' = not(GRACE_BY_COVER and eCover),
    phase' = 1,
    coverState' = coverState, coverRetired' = coverRetired,
    inputHas' = inputHas, eCover' = eCover,
  }

  // Under the exclusive lock: flush the covering pair, then unlink the input
  // and every other pair of the run.
  // The recheck keeps the input unless an output or a covering pair is still
  // there.
  action retire = all {
    phase == 1,
    outHas or counts,
    inputHas' = false,
    coverState' =
      if (coverRetired) 0
      else if (SKIP_FLUSH) coverState
      else if (coverState > 0) 2
      else 0,
    phase' = 2,
    coverRetired' = coverRetired, outHas' = outHas,
    eCover' = eCover, eOut' = eOut,
  }

  action crash = all {
    coverState' = if (coverState == 1) 0 else coverState,
    coverRetired' = coverRetired, inputHas' = inputHas, outHas' = outHas,
    eCover' = eCover, eOut' = eOut, phase' = phase,
  }

  action step = any { copy, retire, crash }

  val noLiveObjectLost = phase < 2 or inputHas or outHas or coverState > 0
  // An unreachable entry inside grace keeps a copy with that pack's own age.
  val graceKept = phase < 2 or eOut
}

module copyRetire {
  import copyRetireCore(RELY_ON_RETIRED = false, SKIP_FLUSH = false, GRACE_BY_COVER = false).*
}

module relyOnRetired {
  import copyRetireCore(RELY_ON_RETIRED = true, SKIP_FLUSH = false, GRACE_BY_COVER = false).*
}

module skipFlush {
  import copyRetireCore(RELY_ON_RETIRED = false, SKIP_FLUSH = true, GRACE_BY_COVER = false).*
}

module graceByCover {
  import copyRetireCore(RELY_ON_RETIRED = false, SKIP_FLUSH = false, GRACE_BY_COVER = true).*
}
