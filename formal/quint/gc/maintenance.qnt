// One old pack, one root, and a publisher that takes the same worktree
// lock as retirement. The object is immutable. A publisher can reuse it
// only while it is present.
module maintenanceModel {
  const CHECK_ROOTS: bool

  var present: bool
  var rooted: bool
  var marked: bool
  var captured: bool
  var gcLocked: bool

  action init = all {
    present' = true,
    rooted' = false,
    marked' = false,
    captured' = false,
    gcLocked' = false,
  }

  action publish = all {
    not(gcLocked),
    present,
    rooted' = true,
    present' = present, marked' = marked, captured' = captured, gcLocked' = gcLocked,
  }

  action unpublish = all {
    not(gcLocked),
    rooted' = false,
    present' = present, marked' = marked, captured' = captured, gcLocked' = gcLocked,
  }

  action mark = all {
    not(gcLocked),
    marked' = true,
    captured' = rooted,
    present' = present, rooted' = rooted, gcLocked' = gcLocked,
  }

  action lock = all {
    marked,
    not(captured),
    not(gcLocked),
    gcLocked' = true,
    present' = present, rooted' = rooted, marked' = marked, captured' = captured,
  }

  action finish = all {
    gcLocked,
    present' = if (CHECK_ROOTS and rooted != captured) present else false,
    marked' = false,
    gcLocked' = false,
    rooted' = rooted, captured' = captured,
  }

  action step = any { publish, unpublish, mark, lock, finish }

  val noLiveObjectLost = not(rooted) or present
}

module checked {
  import maintenanceModel(CHECK_ROOTS = true).*

  run changedRootsKeepThePackTest =
    init.then(mark).then(publish).then(lock).then(finish)
      .expect(rooted and present)

  run replacedRootsAllowRetirementTest =
    init.then(mark).then(publish).then(unpublish).then(lock).then(finish)
      .expect(not(rooted) and not(present))
}

module skipRootCheck {
  import maintenanceModel(CHECK_ROOTS = false).*

  run staleMarkLosesALiveObjectTest =
    init.then(mark).then(publish).then(lock).then(finish)
      .expect(not(noLiveObjectLost))
}
