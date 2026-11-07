// -*- mode: Bluespec; -*-
// Multi-ref commits on the file transport (SPEC-REFS §5.1.3).
//
// A commit takes the stripe locks of its refs in ascending stripe order,
// makes an intent record durable (the commit point), writes each ref file,
// then removes the record. A single-ref write takes its stripe. A writer
// whose stripes hold a pending record finishes it first: the record's
// stripes are taken and every named ref still at its old id gets the new
// one (one step here, since it runs under the record's stripes). A process
// can crash at any point and leave its record. Readers take no lock: a read
// of a ref named in a pending record whose file still holds the old id
// reports the new one.
//
// `logical` is the ghost state a linearizable store would hold: a commit
// changes every named ref at its commit point, a single write at its
// rename. `Atomic` says every read returns it, so no state with some named
// refs new and others old is ever visible, before or after a crash.
// The repo lock is not modelled: no step here takes it exclusive.
module commitModel {
  type Faults = {
    noOverlay: bool,       // readers ignore pending records
    partialRecovery: bool, // a recovering writer finishes only the refs in its own stripes
    noRecovery: bool,      // a writer ignores pending records on its stripes
    descending: bool,      // one process takes a commit's stripes in descending order
  }

  const PROCS: Set[str]
  const REFS: Set[int]
  const STRIPE: int -> int
  const VALUES: Set[int]
  const MAXOPS: int
  const MAXCRASH: int
  const FAULTS: Faults

  type Op = { commit: bool, refs: Set[int], v: int }
  type Record = { refs: Set[int], old: int -> int, v: int }

  var pc: str -> str               // idle | acq | work | apply
  var op: str -> Op
  var need: str -> List[int]       // stripes to take, in order
  var held: str -> Set[int]
  var owner: int -> str            // "" when free
  var file: int -> int
  var logical: int -> int
  var records: Set[Record]
  var mine: str -> Record          // the record a committer wrote
  var left: str -> Set[int]        // refs a committer has still to write
  var ops: int
  var crashes: int

  pure val FREE = ""
  pure val NOREC: Record = { refs: Set(), old: Map(), v: 0 }

  def stripesOf(refs: Set[int]): Set[int] = refs.map(r => STRIPE.get(r))

  // `s` in ascending (or, mutated, descending) order.
  def ordered(s: Set[int], desc: bool): List[int] =
    s.fold([], (acc, x) => acc.append(x)).foldl([], (acc, x) =>
      // insertion sort
      val before = acc.select(y => if (desc) y > x else y < x)
      val after = acc.select(y => if (desc) y <= x else y >= x)
      before.append(x).concat(after))

  def visible(r: int): int =
    val hits = records.filter(rec => rec.refs.contains(r) and rec.old.get(r) == file.get(r))
    if (FAULTS.noOverlay or hits == Set()) file.get(r)
    else hits.fold(file.get(r), (_, rec) => rec.v)

  action init = all {
    pc' = PROCS.mapBy(_ => "idle"),
    op' = PROCS.mapBy(_ => { commit: false, refs: Set(), v: 0 }),
    need' = PROCS.mapBy(_ => []),
    held' = PROCS.mapBy(_ => Set()),
    owner' = REFS.map(r => STRIPE.get(r)).mapBy(_ => FREE),
    file' = REFS.mapBy(_ => 0),
    logical' = REFS.mapBy(_ => 0),
    records' = Set(),
    mine' = PROCS.mapBy(_ => NOREC),
    left' = PROCS.mapBy(_ => Set()),
    ops' = 0,
    crashes' = 0,
  }

  action begin(p: str, o: Op): bool = all {
    pc.get(p) == "idle",
    ops < MAXOPS,
    pc' = pc.set(p, "acq"),
    op' = op.set(p, o),
    need' = need.set(p, ordered(stripesOf(o.refs), o.commit and FAULTS.descending and p == "q")),
    ops' = ops + 1,
    held' = held, owner' = owner, file' = file, logical' = logical, records' = records,
    mine' = mine, left' = left, crashes' = crashes,
  }

  // Take the next stripe once it is free.
  action acquire(p: str): bool = all {
    pc.get(p) == "acq",
    held.get(p).size() < need.get(p).length(),
    val s = need.get(p)[held.get(p).size()]
    all {
      owner.get(s) == FREE,
      owner' = owner.set(s, p),
      held' = held.set(p, held.get(p).union(Set(s))),
    },
    pc' = pc, op' = op, need' = need, file' = file, logical' = logical, records' = records,
    mine' = mine, left' = left, ops' = ops, crashes' = crashes,
  }

  def orphansOn(p: str): Set[Record] =
    records.filter(rec => stripesOf(rec.refs).exists(s => held.get(p).contains(s)))

  // All stripes held and no pending record on them: do the step.
  action start(p: str): bool = all {
    pc.get(p) == "acq",
    held.get(p).size() == need.get(p).length(),
    FAULTS.noRecovery or orphansOn(p) == Set(),
    val o = op.get(p)
    if (o.commit) all {
      val rec = { refs: o.refs, old: o.refs.mapBy(r => file.get(r)), v: o.v }
      all {
        records' = records.union(Set(rec)),
        mine' = mine.set(p, rec),
      },
      logical' = o.refs.fold(logical, (l, r) => l.set(r, o.v)),
      left' = left.set(p, o.refs),
      pc' = pc.set(p, "apply"),
      file' = file, owner' = owner, held' = held,
    } else all {
      // A single-ref write: the rename is its commit point.
      file' = o.refs.fold(file, (f, r) => f.set(r, o.v)),
      logical' = o.refs.fold(logical, (l, r) => l.set(r, o.v)),
      pc' = pc.set(p, "idle"),
      owner' = held.get(p).fold(owner, (w, s) => w.set(s, FREE)),
      held' = held.set(p, Set()),
      records' = records, mine' = mine, left' = left,
    },
    op' = op, need' = need, ops' = ops, crashes' = crashes,
  }

  // A pending record on the held stripes: release, finish it under its own
  // stripes (all free), and start again.
  action recover(p: str, rec: Record): bool = all {
    pc.get(p) == "acq",
    held.get(p).size() == need.get(p).length(),
    not(FAULTS.noRecovery),
    orphansOn(p).contains(rec),
    val released = held.get(p).fold(owner, (w, s) => w.set(s, FREE))
    val mineOnly = rec.refs.filter(r => held.get(p).contains(STRIPE.get(r)))
    val todo = if (FAULTS.partialRecovery) mineOnly else rec.refs
    all {
      stripesOf(rec.refs).forall(s => released.get(s) == FREE),
      file' = todo.fold(file, (f, r) => if (f.get(r) == rec.old.get(r)) f.set(r, rec.v) else f),
      owner' = released,
    },
    records' = records.exclude(Set(rec)),
    held' = held.set(p, Set()),
    pc' = pc, op' = op, need' = need, logical' = logical, mine' = mine, left' = left,
    ops' = ops, crashes' = crashes,
  }

  // A committer writes one more ref file; after the last it removes its
  // record and releases.
  action apply(p: str, r: int): bool = all {
    pc.get(p) == "apply",
    left.get(p).contains(r),
    file' = file.set(r, op.get(p).v),
    val rest = left.get(p).exclude(Set(r))
    all {
      left' = left.set(p, rest),
      if (rest == Set()) all {
        records' = records.exclude(Set(mine.get(p))),
        pc' = pc.set(p, "idle"),
        owner' = held.get(p).fold(owner, (w, s) => w.set(s, FREE)),
        held' = held.set(p, Set()),
      } else all {
        records' = records, pc' = pc, owner' = owner, held' = held,
      },
    },
    op' = op, need' = need, logical' = logical, mine' = mine, ops' = ops, crashes' = crashes,
  }

  // A process dies: the kernel releases its locks; its files and record
  // stay.
  action crash(p: str): bool = all {
    pc.get(p) != "idle",
    crashes < MAXCRASH,
    pc' = pc.set(p, "idle"),
    owner' = held.get(p).fold(owner, (w, s) => w.set(s, FREE)),
    held' = held.set(p, Set()),
    left' = left.set(p, Set()),
    crashes' = crashes + 1,
    op' = op, need' = need, file' = file, logical' = logical, records' = records,
    mine' = mine, ops' = ops,
  }

  action step = {
    nondet p = PROCS.oneOf()
    any {
      nondet refs = REFS.powerset().filter(s => s != Set()).oneOf()
      nondet v = VALUES.oneOf()
      nondet commit = Set(true, false).oneOf()
      all { commit or refs.size() == 1, begin(p, { commit: commit, refs: refs, v: v }) },
      acquire(p),
      start(p),
      nondet rec = records.union(Set(NOREC)).oneOf()
      recover(p, rec),
      nondet r = REFS.oneOf()
      apply(p, r),
      crash(p),
    }
  }

  // ---- invariants
  // Every read returns the linearized state: never some named refs new and
  // others old.
  val Atomic: bool = REFS.forall(r => visible(r) == logical.get(r))

  // No two processes each wait for a stripe the other holds.
  def waitsOn(p: str, q: str): bool =
    pc.get(p) == "acq" and held.get(p).size() < need.get(p).length()
      and owner.get(need.get(p)[held.get(p).size()]) == q
  val NoDeadlock: bool = PROCS.forall(p => PROCS.forall(q => not(p != q and waitsOn(p, q) and waitsOn(q, p))))

  val Safety: bool = Atomic and NoDeadlock

  // ---- non-vacuity
  // A crash leaves a record that a later write finishes.
  val CanaryNoRecordLeft: bool = not(records != Set() and PROCS.forall(p => pc.get(p) == "idle"))
  // Two commits hold stripes at once.
  val CanaryNoParallelCommits: bool =
    not(PROCS.exists(p => PROCS.exists(q => p != q and pc.get(p) == "apply" and pc.get(q) == "apply")))

  action q_init = init
  action q_step = step
  val q_inv = Safety
}

// Refs 0 and 1 in stripes 0 and 1, ref 2 shares stripe 1 with ref 1.
module commit2 {
  import commitModel(PROCS = Set("p", "q"), REFS = Set(0, 1, 2), STRIPE = Map(0 -> 0, 1 -> 1, 2 -> 1),
    VALUES = Set(1, 2), MAXOPS = 4, MAXCRASH = 1,
    FAULTS = { noOverlay: false, partialRecovery: false, noRecovery: false, descending: false }).*
}
module commit2_noOverlay {        // Atomic
  import commitModel(PROCS = Set("p", "q"), REFS = Set(0, 1, 2), STRIPE = Map(0 -> 0, 1 -> 1, 2 -> 1),
    VALUES = Set(1, 2), MAXOPS = 4, MAXCRASH = 1,
    FAULTS = { noOverlay: true, partialRecovery: false, noRecovery: false, descending: false }).*
}
module commit2_partialRecovery {  // Atomic
  import commitModel(PROCS = Set("p", "q"), REFS = Set(0, 1, 2), STRIPE = Map(0 -> 0, 1 -> 1, 2 -> 1),
    VALUES = Set(1, 2), MAXOPS = 4, MAXCRASH = 1,
    FAULTS = { noOverlay: false, partialRecovery: true, noRecovery: false, descending: false }).*
}
module commit2_noRecovery {       // Atomic
  import commitModel(PROCS = Set("p", "q"), REFS = Set(0, 1, 2), STRIPE = Map(0 -> 0, 1 -> 1, 2 -> 1),
    VALUES = Set(1, 2), MAXOPS = 4, MAXCRASH = 1,
    FAULTS = { noOverlay: false, partialRecovery: false, noRecovery: true, descending: false }).*
}
module commit2_descending {       // NoDeadlock
  import commitModel(PROCS = Set("p", "q"), REFS = Set(0, 1, 2), STRIPE = Map(0 -> 0, 1 -> 1, 2 -> 1),
    VALUES = Set(1, 2), MAXOPS = 4, MAXCRASH = 1,
    FAULTS = { noOverlay: false, partialRecovery: false, noRecovery: false, descending: true }).*
}
