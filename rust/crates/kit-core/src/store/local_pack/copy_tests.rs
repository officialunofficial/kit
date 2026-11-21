//! Copy-then-retire: what `kit gc` rewrites, merges and retires as covered.
//!
//! Ages: a pack is old at `OLD` and young at `YOUNG`, for `NOW` and `GRACE`.
//! A pack that a run writes carries the wall clock, which is later than
//! `NOW`, so it is young.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

use super::tests::{
    blob, damage_frame, fresh, manifest_root, publish_objects, record_io, set_after_copy_publish,
    set_pack_age, take_io,
};
use super::{Index, Pair};
use crate::hash::Hash;
use crate::layout::RepoLayout;
use crate::ops::gc::{GcReport, run_gc};
use crate::store::ObjectStore;

const NOW: u64 = 100;
const GRACE: u64 = 10;
const OLD: u64 = 1;
const YOUNG: u64 = 95;

fn obj(label: &str, len: usize) -> Vec<u8> {
    let mut data = label.as_bytes().to_vec();
    data.resize(len.max(data.len()), b'.');
    blob(&data)
}

fn run(store: &ObjectStore, layout: &RepoLayout, dry_run: bool) -> GcReport {
    run_gc(store, layout, NOW, GRACE, dry_run, &mut |_, _, _| {}).unwrap()
}

fn publish(store: &ObjectStore, objects: &[&Vec<u8>], age: u64) -> (Pair, Vec<Hash>) {
    let bodies: Vec<&[u8]> = objects.iter().map(|bytes| bytes.as_slice()).collect();
    let (pair, ids) = publish_objects(store, &bodies);
    set_pack_age(&pair.pack, age);
    (pair, ids)
}

fn keep(layout: &RepoLayout, name: &str, id: &Hash) {
    crate::refs::write_ref(layout, name, id).unwrap();
}

fn packs(store: &ObjectStore) -> Vec<PathBuf> {
    let mut packs: Vec<_> = fs::read_dir(store.pack_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pack"))
        .collect();
    packs.sort();
    packs
}

fn exists(pair: &Pair) -> bool {
    pair.pack.exists() && pair.index.exists()
}

/// Flip one payload byte of `id` in `pair`, keeping the pack's age.
fn damage(pair: &Pair, id: &Hash, age: u64) {
    let frame = Index::open(pair).unwrap().find(id).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&pair.pack).unwrap();
    file.seek(SeekFrom::Start(frame.offset + 16)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    set_pack_age(&pair.pack, age);
}

/// Flip one byte of the frame length that precedes `id`, keeping the pack's
/// age. The index then disagrees with the pack about the frame.
fn damage_header(pair: &Pair, id: &Hash, age: u64) {
    let frame = Index::open(pair).unwrap().find(id).unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(&pair.pack).unwrap();
    file.seek(SeekFrom::Start(frame.offset - 4)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    set_pack_age(&pair.pack, age);
}

fn sizes(objects: &[&Vec<u8>]) -> u64 {
    objects.iter().map(|bytes| bytes.len() as u64).sum()
}

#[test]
fn a_mostly_dead_pack_past_grace_is_rewritten_and_retirement_survives_its_own_guard() {
    let (_dir, layout, store) = fresh();
    let live = obj("live", 2000);
    let dead: Vec<_> = (0..9).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let mut all = vec![&live];
    all.extend(dead.iter());
    let (pair, ids) = publish(&store, &all, OLD);
    keep(&layout, "live", &ids[0]);

    let preview = run(&store, &layout, true);
    assert_eq!(preview.packs_rewritten, 1);
    assert_eq!(preview.survivor_bytes_copied, live.len() as u64);
    assert_eq!(
        preview.duplicate_bytes_reclaimed,
        sizes(&dead.iter().collect::<Vec<_>>())
    );
    assert!(exists(&pair));
    assert_eq!(packs(&store).len(), 1);

    // The copy holds the shared guard. Retirement tries the exclusive lock in
    // the same process, so the guard must be gone by then.
    let report = run(&store, &layout, false);
    assert_eq!(report.packs_rewritten, 1);
    assert_eq!(report.packs_merged + report.packs_retired_covered, 0);
    assert_eq!(report.survivor_bytes_copied, live.len() as u64);
    assert_eq!(
        report.duplicate_bytes_reclaimed,
        preview.duplicate_bytes_reclaimed
    );
    assert_eq!(report.bytes_reclaimed, preview.bytes_reclaimed);
    assert!(report.bytes_reclaimed > 0);
    assert!(!pair.pack.exists() && !pair.index.exists());
    assert_eq!(packs(&store).len(), 1);
    assert_eq!(store.read(&ids[0]).unwrap(), live);
    for id in &ids[1..] {
        assert!(!store.contains(id));
    }
    assert_eq!(store.check_local_packs(false).unwrap(), 0);
}

#[test]
fn a_pack_inside_grace_and_a_lightly_dead_pack_stay() {
    let (_dir, layout, store) = fresh();
    let live = obj("live", 2000);
    let dead: Vec<_> = (0..9).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let mut young = vec![&live];
    young.extend(dead.iter());
    let (young_pair, young_ids) = publish(&store, &young, YOUNG);
    keep(&layout, "young", &young_ids[0]);

    let lives: Vec<_> = (0..4).map(|n| obj(&format!("l{n}"), 2000)).collect();
    let one_dead = obj("one dead", 2000);
    let mut light = lives.iter().collect::<Vec<_>>();
    light.push(&one_dead);
    let (light_pair, light_ids) = publish(&store, &light, OLD);
    for (n, id) in light_ids[..4].iter().enumerate() {
        keep(&layout, &format!("light{n}"), id);
    }

    for dry_run in [true, false] {
        let report = run(&store, &layout, dry_run);
        assert_eq!(
            report.packs_rewritten + report.packs_merged + report.packs_retired_covered,
            0
        );
        assert_eq!(report.survivor_bytes_copied, 0);
        assert!(exists(&young_pair) && exists(&light_pair));
    }
}

#[test]
fn two_packs_with_the_same_ids_retire_one_as_covered_and_the_same_one_every_time() {
    let (_dir, layout, store) = fresh();
    let a = obj("a", 500);
    let b = obj("b", 500);
    let (first, ids) = publish(&store, &[&a, &b], 50);
    let (second, _) = publish(&store, &[&b, &a], 50);
    assert_ne!(first.key, second.key);
    keep(&layout, "a", &ids[0]);
    keep(&layout, "b", &ids[1]);

    let report = run(&store, &layout, false);
    assert_eq!(report.packs_retired_covered, 1, "{report:?}");
    assert_eq!(report.survivor_bytes_copied, 0);
    // Equal ages: the lower key is the home, and the other pack goes.
    let (home, gone) = if first.key < second.key {
        (&first, &second)
    } else {
        (&second, &first)
    };
    assert!(exists(home));
    assert!(!gone.pack.exists() && !gone.index.exists());
    assert_eq!(store.read(&ids[0]).unwrap(), a);
    assert_eq!(store.read(&ids[1]).unwrap(), b);
}

#[test]
fn the_report_names_how_long_retirement_held_the_exclusive_lock() {
    let (_dir, layout, store) = fresh();
    let x = obj("x", 2000);
    let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let mut all = vec![&x];
    all.extend(dead.iter());
    let (_, ids) = publish(&store, &all, OLD);
    keep(&layout, "x", &ids[0]);

    // A dry run and a run with nothing to retire never take the lock.
    assert_eq!(run(&store, &layout, true).retire_hold_ms, 0);
    let report = run(&store, &layout, false);
    assert_eq!(report.packs_rewritten, 1);
    let held = ObjectStore::last_sweep_hold().as_millis();
    assert_eq!(u128::from(report.retire_hold_ms), held);
    assert_eq!(run(&store, &layout, false).retire_hold_ms, 0);
}

#[test]
fn a_live_chunk_with_a_damaged_payload_is_never_dropped_for_a_copy_and_never_copied() {
    // The mark checks a packed chunk by its head only, so a bad payload
    // passes it and reaches copy-then-retire.
    for covered in [false, true] {
        let (_dir, layout, store) = fresh();
        let chunk = obj("chunk", 4096);
        let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 4096)).collect();
        let mut all = vec![&chunk];
        all.extend(dead.iter());
        let (input, ids) = publish(&store, &all, OLD);
        manifest_root(&store, &layout, "live", &ids[..1]);
        damage_frame(&input, &ids[0], 10, |byte| *byte ^= 1);
        set_pack_age(&input.pack, OLD);
        let healthy = covered.then(|| publish(&store, &[&chunk], YOUNG).0);

        let report = run(&store, &layout, false);
        assert_eq!(report.pack_copy_error, None, "{covered}");
        if let Some(healthy) = healthy {
            // A verified healthy copy stays; the damaged pack may go.
            assert!(exists(&healthy));
            assert_eq!(store.read(&ids[0]).unwrap(), chunk);
        } else {
            // No other copy: the damaged input stays and is reported.
            assert!(exists(&input));
            assert_eq!(report.packs_rewritten, 0);
            assert_eq!(report.skipped_pack_errors.len(), 1);
            assert!(store.read(&ids[0]).is_err());
        }
    }
}

#[test]
fn a_young_pack_with_no_dead_entry_that_another_pack_covers_is_retired_as_covered() {
    let (_dir, layout, store) = fresh();
    let a = obj("a", 500);
    let b = obj("b", 500);
    let (older, ids) = publish(&store, &[&a, &b], YOUNG - 1);
    let (younger, _) = publish(&store, &[&b, &a], YOUNG);
    keep(&layout, "a", &ids[0]);
    keep(&layout, "b", &ids[1]);

    let report = run(&store, &layout, false);
    assert_eq!(report.packs_retired_covered, 1, "{report:?}");
    assert_eq!(report.survivor_bytes_copied, 0);
    assert!(!exists(&older), "the older pack goes");
    assert!(exists(&younger), "the younger pack is the home");
    assert_eq!(store.read(&ids[0]).unwrap(), a);
    assert_eq!(store.read(&ids[1]).unwrap(), b);
}

#[cfg(unix)]
#[test]
fn a_covering_copy_that_cannot_be_read_stops_the_run_and_keeps_every_pack() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, layout, store) = fresh();
    let a = obj("a", 500);
    let b = obj("b", 500);
    let (older, ids) = publish(&store, &[&a, &b], YOUNG - 1);
    let (younger, _) = publish(&store, &[&b, &a], YOUNG);
    keep(&layout, "a", &ids[0]);
    keep(&layout, "b", &ids[1]);

    fs::set_permissions(&younger.pack, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&younger.pack).is_err() {
        let error = run_gc(&store, &layout, NOW, GRACE, false, &mut |_, _, _| {}).unwrap_err();
        assert!(
            matches!(&error, crate::store::StoreError::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "{error:?}"
        );
        assert!(exists(&older) && exists(&younger), "nothing was retired");
    }
    fs::set_permissions(&younger.pack, fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn a_live_id_whose_only_other_copy_is_in_another_input_is_copied_once() {
    let (_dir, layout, store) = fresh();
    let x = obj("shared live", 2000);
    let dead_p: Vec<_> = (0..4).map(|n| obj(&format!("p{n}"), 2000)).collect();
    let dead_q: Vec<_> = (0..4).map(|n| obj(&format!("q{n}"), 2000)).collect();
    let mut p = vec![&x];
    p.extend(dead_p.iter());
    let mut q = vec![&x];
    q.extend(dead_q.iter());
    let (p_pair, ids) = publish(&store, &p, 40);
    let (q_pair, _) = publish(&store, &q, OLD);
    keep(&layout, "x", &ids[0]);

    let report = run(&store, &layout, false);
    assert_eq!(report.packs_rewritten, 2);
    assert_eq!(report.survivor_bytes_copied, x.len() as u64);
    assert!(!exists(&p_pair) && !exists(&q_pair));
    assert_eq!(packs(&store).len(), 1);
    assert_eq!(store.read(&ids[0]).unwrap(), x);
}

#[test]
fn a_damaged_covering_copy_is_not_relied_on_and_the_entry_is_copied() {
    let (_dir, layout, store) = fresh();
    let x = obj("x", 2000);
    let y = obj("y", 2000);
    let dead: Vec<_> = (0..3).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let (stays, ids) = publish(&store, &[&x, &y], YOUNG);
    let mut input = vec![&x];
    input.extend(dead.iter());
    let (retired, _) = publish(&store, &input, OLD);
    keep(&layout, "x", &ids[0]);
    keep(&layout, "y", &ids[1]);
    damage(&stays, &ids[0], YOUNG);

    let report = run(&store, &layout, false);
    assert_eq!(report.skipped_pack_errors.len(), 1);
    assert_eq!(report.packs_rewritten, 1);
    assert_eq!(report.survivor_bytes_copied, x.len() as u64);
    assert!(!exists(&retired));
    assert!(exists(&stays));
    assert_eq!(store.read(&ids[0]).unwrap(), x);
}

#[test]
fn small_packs_merge_only_from_eight_and_a_large_pack_is_never_an_input() {
    for count in [7, 12] {
        let (_dir, layout, store) = fresh();
        let objects: Vec<_> = (0..count)
            .map(|n| obj(&format!("small{n}"), 1000))
            .collect();
        let pairs: Vec<_> = objects
            .iter()
            .enumerate()
            .map(|(n, bytes)| {
                let (pair, ids) = publish(&store, &[bytes], OLD);
                keep(&layout, &format!("small{n}"), &ids[0]);
                (pair, ids[0])
            })
            .collect();
        let large = obj("large", 17 << 20);
        let (large_pair, large_ids) = publish(&store, &[&large], OLD);
        keep(&layout, "large", &large_ids[0]);

        let report = run(&store, &layout, false);
        assert!(exists(&large_pair), "a pack of 16 MiB or more stays");
        if count < 8 {
            assert_eq!(report.packs_merged, 0);
            assert_eq!(packs(&store).len(), count + 1);
        } else {
            assert_eq!(report.packs_merged, count);
            assert_eq!(packs(&store).len(), 2);
        }
        for ((pair, id), bytes) in pairs.iter().zip(&objects) {
            assert_eq!(exists(pair), count < 8);
            assert_eq!(&store.read(id).unwrap(), bytes);
        }
    }
}

#[test]
fn a_pack_of_sixteen_thousand_entries_is_not_small() {
    // 16,383 entries are small and 16,384 are not. Seven small packs beside
    // the edge pack make eight only when it counts. A dry run classifies
    // without copying the entries.
    for (entries, merges) in [(16_383, true), (16_384, false)] {
        let (_dir, layout, store) = fresh();
        for n in 0..7 {
            publish(&store, &[&obj(&format!("tiny{n}"), 500)], YOUNG);
        }
        let edge: Vec<_> = (0..entries).map(|n| obj(&format!("e{n}"), 20)).collect();
        publish(&store, &edge.iter().collect::<Vec<_>>(), YOUNG);

        let report = run(&store, &layout, true);
        assert_eq!(report.packs_merged, if merges { 8 } else { 0 }, "{entries}");
    }
}

#[test]
fn a_damaged_input_frame_keeps_that_input_and_the_others_proceed() {
    // The mark refuses a damaged live blob reached as a file, so the damage
    // sits in an unreachable entry that survives inside grace. A damaged live
    // chunk is the next test.
    let (_dir, layout, store) = fresh();
    let objects: Vec<_> = (0..9).map(|n| obj(&format!("young{n}"), 2000)).collect();
    let pairs: Vec<_> = objects
        .iter()
        .map(|bytes| publish(&store, &[bytes], YOUNG))
        .collect();
    damage(&pairs[0].0, &pairs[0].1[0], YOUNG);

    let report = run(&store, &layout, false);
    assert_eq!(report.skipped_pack_errors.len(), 1);
    assert_eq!(report.packs_merged, 8);
    assert!(exists(&pairs[0].0), "the damaged input stays");
    for (pair, _) in &pairs[1..] {
        assert!(!exists(pair));
    }
    for ((_, ids), bytes) in pairs.iter().zip(&objects).skip(1) {
        assert_eq!(&store.read(&ids[0]).unwrap(), bytes);
    }
}

#[test]
fn a_frame_the_index_and_the_pack_disagree_on_keeps_that_input_and_the_others_proceed() {
    let (_dir, layout, store) = fresh();
    let objects: Vec<_> = (0..9).map(|n| obj(&format!("young{n}"), 2000)).collect();
    let pairs: Vec<_> = objects
        .iter()
        .map(|bytes| publish(&store, &[bytes], YOUNG))
        .collect();
    damage_header(&pairs[0].0, &pairs[0].1[0], YOUNG);

    let report = run(&store, &layout, false);
    assert_eq!(report.pack_copy_error, None);
    assert_eq!(report.skipped_pack_errors.len(), 1);
    assert_eq!(report.packs_merged, 8);
    assert!(exists(&pairs[0].0), "the damaged input stays");
    for (pair, _) in &pairs[1..] {
        assert!(!exists(pair));
    }
}

#[test]
fn a_crash_after_the_outputs_publish_loses_nothing_and_the_next_run_copies_nothing() {
    let (_dir, layout, store) = fresh();
    let x = obj("x", 2000);
    let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let mut all = vec![&x];
    all.extend(dead.iter());
    let (pair, ids) = publish(&store, &all, OLD);
    keep(&layout, "x", &ids[0]);

    set_after_copy_publish(|| Err(std::io::Error::other("crash after publish").into()));
    assert!(run_gc(&store, &layout, NOW, GRACE, false, &mut |_, _, _| {}).is_err());
    assert!(exists(&pair));
    assert_eq!(packs(&store).len(), 2);
    let reopened = ObjectStore::open(&layout).unwrap();
    assert_eq!(reopened.read(&ids[0]).unwrap(), x);

    let report = run(&store, &layout, false);
    assert_eq!(report.survivor_bytes_copied, 0);
    assert_eq!(report.packs_retired_covered, 1);
    assert!(!exists(&pair));
    assert_eq!(packs(&store).len(), 1);
    assert_eq!(store.read(&ids[0]).unwrap(), x);
}

#[test]
fn a_crash_after_the_input_pack_unlinks_leaves_a_lone_index_and_the_store_reads() {
    use crate::ops::gc::live_objects;

    let (_dir, layout, store) = fresh();
    let x = obj("x", 2000);
    let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let mut all = vec![&x];
    all.extend(dead.iter());
    let (pair, ids) = publish(&store, &all, OLD);
    set_pack_age(&pair.index, OLD);
    keep(&layout, "x", &ids[0]);

    let live = live_objects(&store, &layout).unwrap();
    let mut report = GcReport::default();
    let sweep = store
        .plan_pack_sweep(&live, NOW, GRACE, &mut report)
        .unwrap();
    let result = sweep.run_with(&store, &mut report, || {
        assert!(!pair.pack.exists());
        assert!(pair.index.is_file());
        Err(std::io::Error::other("crash between pack and index unlinks").into())
    });
    assert!(result.is_err());
    let reopened = ObjectStore::open(&layout).unwrap();
    assert_eq!(reopened.read(&ids[0]).unwrap(), x);
    assert_eq!(reopened.check_local_packs(true).unwrap(), 0);

    let report = run(&reopened, &layout, false);
    assert_eq!(report.pack_leftovers_pruned, 1);
    assert!(!pair.pack.exists() && !pair.index.exists());
    assert_eq!(reopened.read(&ids[0]).unwrap(), x);
}

#[test]
fn an_unreachable_entry_inside_grace_survives_whatever_older_copies_exist() {
    // A small merge reaches a young pack that holds an unreachable id which an
    // older pack also holds. The merge must copy it, not drop it.
    let (_dir, layout, store) = fresh();
    let big = |label: &str| obj(label, 3_600_000);
    let e = big("e");
    let lives: Vec<_> = (0..4).map(|n| big(&format!("live{n}"))).collect();
    let mut older = lives.iter().collect::<Vec<_>>();
    older.push(&e);
    let (older_pair, older_ids) = publish(&store, &older, OLD);
    for (n, id) in older_ids[..4].iter().enumerate() {
        keep(&layout, &format!("live{n}"), id);
    }
    let e_id = older_ids[4];

    let small: Vec<_> = (0..8).map(|n| obj(&format!("small{n}"), 1000)).collect();
    let mut young_ids = Vec::new();
    for (n, bytes) in small.iter().enumerate() {
        let (_, ids) = if n == 0 {
            publish(&store, &[bytes, &e], YOUNG)
        } else {
            publish(&store, &[bytes], YOUNG)
        };
        young_ids.push(ids);
    }

    let report = run(&store, &layout, false);
    assert_eq!(report.packs_merged, 8);
    assert!(
        exists(&older_pair),
        "the older pack stays below the threshold"
    );
    // Drop the older copy by hand. The merged output still holds `e`.
    fs::remove_file(&older_pair.pack).unwrap();
    fs::remove_file(&older_pair.index).unwrap();
    let reopened = ObjectStore::open(&layout).unwrap();
    assert_eq!(reopened.read(&e_id).unwrap(), e);
    for (ids, bytes) in young_ids.iter().zip(&small) {
        assert_eq!(&reopened.read(&ids[0]).unwrap(), bytes);
    }
}

#[test]
fn an_unreachable_entry_in_a_pack_inside_grace_outlives_an_older_copy_that_goes() {
    for older_is_wholly_dead in [false, true] {
        let (_dir, layout, store) = fresh();
        let e = obj("e", 2000);
        let filler: Vec<_> = (0..4).map(|n| obj(&format!("filler{n}"), 2000)).collect();
        let live = obj("live", 2000);
        let mut older = vec![&e];
        older.extend(filler.iter());
        if !older_is_wholly_dead {
            older.push(&live);
        }
        let (older_pair, older_ids) = publish(&store, &older, OLD);
        if !older_is_wholly_dead {
            keep(&layout, "live", older_ids.last().unwrap());
        }
        let (young_pair, _) = publish(&store, &[&e], YOUNG);

        let report = run(&store, &layout, false);
        assert!(
            !exists(&older_pair),
            "the older pack is retired or rewritten"
        );
        assert_eq!(
            report.packs_retired + report.packs_rewritten,
            1,
            "wholly dead: {older_is_wholly_dead}"
        );
        assert!(exists(&young_pair));
        assert_eq!(store.read(&older_ids[0]).unwrap(), e);
    }
}

#[test]
fn every_covering_pair_is_flushed_before_the_first_unlink() {
    let (_dir, layout, store) = fresh();
    let x = obj("x", 2000);
    let y = obj("y", 2000);
    let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let (stays, ids) = publish(&store, &[&x, &y], YOUNG);
    let mut input = vec![&x, &y];
    input.extend(dead.iter());
    let (retired, _) = publish(&store, &input, OLD);
    keep(&layout, "x", &ids[0]);
    keep(&layout, "y", &ids[1]);

    record_io();
    let report = run(&store, &layout, false);
    let log = take_io();
    assert_eq!(report.packs_retired_covered, 1);
    let first_unlink = log
        .iter()
        .position(|(kind, _)| *kind == "unlink")
        .expect("the input is unlinked");
    let before = &log[..first_unlink];
    for member in [&stays.pack, &stays.index] {
        assert!(
            before
                .iter()
                .any(|(kind, path)| *kind == "sync" && path == member),
            "{member:?} is flushed first"
        );
    }
    for dir in [store.objects_root().to_path_buf(), store.pack_dir()] {
        assert!(
            before
                .iter()
                .any(|(kind, path)| *kind == "sync-dir" && path == &dir),
            "{dir:?} is flushed first"
        );
    }
    assert_eq!(log[first_unlink].1, retired.pack, "packs go before indexes");
    assert!(!exists(&retired));
}

#[test]
fn a_lone_index_never_counts_as_coverage() {
    // A covering pair that loses its pack before the retirement keeps the
    // input in place.
    let (_dir, layout, store) = fresh();
    let x = obj("x", 2000);
    let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let (covering, ids) = publish(&store, &[&x], YOUNG);
    let mut input = vec![&x];
    input.extend(dead.iter());
    let (retired, _) = publish(&store, &input, OLD);
    keep(&layout, "x", &ids[0]);

    let pack = covering.pack.clone();
    set_after_copy_publish(move || {
        fs::remove_file(pack)?;
        Ok(())
    });
    let report = run(&store, &layout, false);
    assert_eq!(report.packs_retired_covered, 0);
    assert!(exists(&retired), "its coverage changed");
    assert!(covering.index.exists() && !covering.pack.exists());
    assert_eq!(store.read(&ids[0]).unwrap(), x);

    // With a lone index from the start there is nothing to rely on: the entry
    // is copied.
    let report = run(&store, &layout, false);
    assert_eq!(report.packs_rewritten, 1);
    assert!(!exists(&retired));
    assert_eq!(store.read(&ids[0]).unwrap(), x);
}

#[test]
fn another_process_holding_the_format_guard_stops_the_retirement_not_the_copy() {
    let (_dir, layout, store) = fresh();
    let x = obj("x", 2000);
    let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let mut all = vec![&x];
    all.extend(dead.iter());
    let (pair, ids) = publish(&store, &all, OLD);
    keep(&layout, "x", &ids[0]);

    let guard = store.prune_guard().unwrap();
    let report = run(&store, &layout, false);
    assert_eq!(report.packs_rewritten, 0);
    assert!(exists(&pair));
    assert_eq!(packs(&store).len(), 2, "the output stays as a duplicate");
    drop(guard);

    let report = run(&store, &layout, false);
    assert_eq!(report.survivor_bytes_copied, 0);
    assert_eq!(report.packs_retired_covered, 1);
    assert!(!exists(&pair));
    assert_eq!(store.read(&ids[0]).unwrap(), x);
}

#[test]
fn an_input_whose_mtime_is_refreshed_before_the_retirement_stays() {
    for member in ["input", "covering"] {
        let (_dir, layout, store) = fresh();
        let x = obj("x", 2000);
        let y = obj("y", 2000);
        let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 2000)).collect();
        let (covering, ids) = publish(&store, &[&x, &y], YOUNG);
        let mut input = vec![&x, &y];
        input.extend(dead.iter());
        let (retired, _) = publish(&store, &input, OLD);
        keep(&layout, "x", &ids[0]);
        keep(&layout, "y", &ids[1]);

        let target = if member == "input" {
            retired.pack.clone()
        } else {
            covering.pack.clone()
        };
        set_after_copy_publish(move || {
            set_pack_age(&target, 97);
            Ok(())
        });
        let report = run(&store, &layout, false);
        assert_eq!(report.packs_retired_covered, 0, "{member}");
        assert!(exists(&retired), "{member}");
        assert_eq!(store.read(&ids[0]).unwrap(), x);
    }
}

#[test]
fn a_reader_with_a_cached_locator_finds_the_object_in_the_output() {
    let (_dir, layout, store) = fresh();
    let x = obj("x", 2000);
    let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let mut all = vec![&x];
    all.extend(dead.iter());
    let (pair, ids) = publish(&store, &all, OLD);
    keep(&layout, "x", &ids[0]);
    let reader = ObjectStore::open(&layout).unwrap();
    assert_eq!(reader.read(&ids[0]).unwrap(), x);

    let report = run(&store, &layout, false);
    assert_eq!(report.packs_rewritten, 1);
    assert!(!exists(&pair));
    assert_eq!(reader.read(&ids[0]).unwrap(), x);
}

#[test]
fn outputs_roll_over_at_the_entry_cap_and_the_payload_cap() {
    use super::copy::{OUTPUT_ENTRIES, OUTPUT_PAYLOAD, Rolling};

    assert_eq!(OUTPUT_ENTRIES, 65_536);
    assert_eq!(OUTPUT_PAYLOAD, 64 << 20);
    let each = obj("object 0", 1000).len() as u64;
    for (entries, payload, expected) in [
        (3, u64::MAX, vec![3, 3, 1]),
        (100, each * 5 / 2, vec![2, 2, 2]),
        // Exactly full: a third object that reaches the cap fits.
        (100, each * 3, vec![3, 3]),
    ] {
        let (_dir, _layout, store) = fresh();
        store.try_activate_local_packs().unwrap();
        let guard = store.prune_guard().unwrap();
        let mut rolling = Rolling::capped(&store, &guard, entries, payload);
        for n in 0..expected.iter().sum::<usize>() {
            let bytes = obj(&format!("object {n}"), 1000);
            let id = crate::object::object_id_from_bytes(&bytes);
            assert!(rolling.write(&id, &bytes).unwrap().is_some());
        }
        let (pairs, ids, _) = rolling.finish().unwrap();
        drop(guard);
        assert_eq!(pairs.iter().flatten().count(), expected.len());
        assert_eq!(ids.iter().map(Vec::len).collect::<Vec<_>>(), expected);
        for pair in pairs.iter().flatten() {
            assert!(exists(pair));
        }
    }
}

#[cfg(feature = "fault-injection")]
#[test]
fn a_write_failure_during_the_copy_keeps_the_inputs_and_the_run_goes_on() {
    let (_dir, layout, store) = fresh();
    let x = obj("x", 2000);
    let dead: Vec<_> = (0..4).map(|n| obj(&format!("dead{n}"), 2000)).collect();
    let mut all = vec![&x];
    all.extend(dead.iter());
    let (pair, ids) = publish(&store, &all, OLD);
    keep(&layout, "x", &ids[0]);

    let failing = crate::fault::fail_writes(crate::fault::Site::Store);
    let report = run(&store, &layout, false);
    drop(failing);
    assert!(report.pack_copy_error.is_some());
    assert_eq!(report.packs_rewritten, 0);
    assert!(exists(&pair));
    assert_eq!(packs(&store).len(), 1, "no output was published");
    assert_eq!(store.read(&ids[0]).unwrap(), x);

    let report = run(&store, &layout, false);
    assert_eq!(report.packs_rewritten, 1);
    assert_eq!(store.read(&ids[0]).unwrap(), x);
}
