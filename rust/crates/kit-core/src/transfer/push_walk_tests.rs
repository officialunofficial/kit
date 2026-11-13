//! Tests of the push walk and of the plan built from it.

use std::collections::{BTreeSet, HashSet};

use proptest::prelude::*;

use super::tests::{
    assert_pack_reconstructs, big_buffer, chunk_content, put, put_blob, put_chunked,
    put_chunked_from, store,
};
use super::walk::{ChunkMemory, HeldCommits, PushWalk, take_counted};
use super::*;
use crate::object::{
    ChunkedBlob, Commit, EntryMode, Identity, Remix, RemixSource, Tag, Tree, TreeEntry,
};
use crate::ops::graph::{check_closure_present, reachable_objects};
use crate::pack::{PackReader, PackWriter};

fn tree_of(s: &ObjectStore, entries: &[(&str, Hash)]) -> Hash {
    let mut entries: Vec<TreeEntry> = entries
        .iter()
        .map(|(name, hash)| TreeEntry {
            name: name.as_bytes().to_vec(),
            mode: match s.object_type(hash).unwrap() {
                ObjectType::Tree => EntryMode::Tree,
                _ => EntryMode::Blob,
            },
            object_hash: *hash,
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    put(s, &Object::Tree(Tree { entries }))
}

fn commit(s: &ObjectStore, tree: Hash, parents: &[Hash], msg: &str) -> Hash {
    put(
        s,
        &Object::Commit(Commit::new_unannotated(
            tree,
            parents.to_vec(),
            Identity::ed25519([7; 32]),
            [0; 32],
            msg.as_bytes().to_vec(),
            msg.len() as u64,
            [0; 64],
        )),
    )
}

/// A file of the given chunk contents, each 400 bytes.
fn file(s: &ObjectStore, seeds: &[u8]) -> Hash {
    let chunks: Vec<Vec<u8>> = seeds.iter().map(|&k| chunk_content(k, 400)).collect();
    put_chunked_from(s, &chunks)
}

fn chunk_id(s: &ObjectStore, seed: u8) -> Hash {
    put_blob(s, chunk_content(seed, 400))
}

fn manifest_chunks(s: &ObjectStore, manifest: &Hash) -> Vec<Hash> {
    match s.read_object(manifest).unwrap() {
        Object::ChunkedBlob(blob) => blob.chunks,
        other => panic!("not a manifest: {other:?}"),
    }
}

fn ids(plan: &PackPlan) -> BTreeSet<Hash> {
    plan.raw
        .iter()
        .copied()
        .chain(plan.deltas.iter().map(|d| d.target))
        .collect()
}

fn closure_bytes(s: &ObjectStore, tip: &Hash) -> Vec<(Hash, Vec<u8>)> {
    reachable_objects(s, tip)
        .unwrap()
        .into_iter()
        .map(|h| (h, s.read(&h).unwrap()))
        .collect()
}

fn remove(s: &ObjectStore, h: &Hash) {
    std::fs::remove_file(s.path_for(h)).unwrap();
}

/// Apply the plan over a store that holds `seed`, and check the closure of
/// `new_tip` is then present.
fn assert_applies(src: &ObjectStore, plan: &PackPlan, seed: &[(Hash, Vec<u8>)], new_tip: Hash) {
    let mut w = PackWriter::new();
    for h in &plan.raw {
        w.push_raw(*h, &src.read(h).unwrap()).unwrap();
    }
    for d in &plan.deltas {
        w.push_delta(&d.base, &d.stream).unwrap();
    }
    let pack = w.finish().unwrap();
    let (_d, dst) = store();
    for (_, bytes) in seed {
        dst.write(bytes).unwrap();
    }
    PackReader::read(&pack, &dst).unwrap();
    assert!(
        !check_closure_present(&dst, [&new_tip]).unwrap(),
        "the closure must be complete and the walk uncut"
    );
}

fn limits(objects: usize) -> WalkLimits {
    WalkLimits {
        objects,
        ..WalkLimits::default()
    }
}

fn sequential(
    s: &ObjectStore,
    candidates: &[DeltaCandidate],
) -> Result<Vec<Option<PlannedDelta>>, StoreError> {
    candidates
        .iter()
        .map(|&c| encode_delta_candidate(s, c))
        .collect()
}

#[test]
fn a_first_push_sends_the_whole_closure_and_is_self_contained() {
    let (_d, s) = store();
    let m = file(&s, &[1, 2, 3]);
    let t = tree_of(&s, &[("f", m)]);
    let c = commit(&s, t, &[], "first");
    let plan = plan_pack(&s, c, None).unwrap();
    assert!(plan.self_contained);
    assert_eq!(ids(&plan), reachable_objects(&s, &c).unwrap());
    assert_eq!(plan.object_count(), 3 + 3);
    assert_applies(&s, &plan, &[], c);
}

#[test]
fn a_remote_tip_this_store_lacks_plans_the_whole_closure() {
    let (_d, s) = store();
    let m = file(&s, &[1, 2, 3]);
    let t = tree_of(&s, &[("f", m)]);
    let c = commit(&s, t, &[], "first");
    let plan = plan_pack(&s, c, Some([9; 32])).unwrap();
    assert!(plan.self_contained);
    assert_eq!(ids(&plan), reachable_objects(&s, &c).unwrap());
    assert_applies(&s, &plan, &[], c);
}

#[test]
fn a_remote_tip_whose_parent_is_absent_still_plans_only_what_is_new() {
    let (_d, s) = store();
    let m1 = file(&s, &[1, 2, 3]);
    let c1 = commit(&s, tree_of(&s, &[("f", m1)]), &[], "one");
    let m2 = file(&s, &[1, 2, 4]);
    let remote = commit(&s, tree_of(&s, &[("f", m2)]), &[c1], "two");
    let seed = closure_bytes(&s, &remote);
    let m3 = file(&s, &[5, 6]);
    let new = commit(&s, tree_of(&s, &[("f", m2), ("g", m3)]), &[remote], "three");
    // The remote's parent commit is gone locally.
    remove(&s, &c1);
    let plan = plan_pack(&s, new, Some(remote)).unwrap();
    assert!(!plan.self_contained);
    let t_new = tree_of(&s, &[("f", m2), ("g", m3)]);
    let expected = BTreeSet::from([new, t_new, m3, chunk_id(&s, 5), chunk_id(&s, 6)]);
    assert_eq!(ids(&plan), expected);
    assert_applies(&s, &plan, &seed, new);
}

#[test]
fn a_force_push_to_unrelated_history_does_not_resend_a_manifest_the_remote_holds() {
    let (_d, s) = store();
    let shared = file(&s, &[1, 2, 3]);
    let remote = commit(&s, tree_of(&s, &[("x", shared)]), &[], "remote");
    let seed = closure_bytes(&s, &remote);
    let other = file(&s, &[7, 8]);
    let new = commit(
        &s,
        tree_of(&s, &[("y", shared), ("z", other)]),
        &[],
        "unrelated",
    );
    let plan = plan_pack(&s, new, Some(remote)).unwrap();
    let sent = ids(&plan);
    assert!(!sent.contains(&shared), "the shared manifest is held");
    for seed in [1, 2, 3] {
        assert!(!sent.contains(&chunk_id(&s, seed)), "chunk {seed} is held");
    }
    assert!(sent.contains(&other));
    assert!(sent.contains(&chunk_id(&s, 7)) && sent.contains(&chunk_id(&s, 8)));
    assert_applies(&s, &plan, &seed, new);
}

#[test]
fn a_new_tip_that_the_remote_holds_plans_nothing() {
    let (_d, s) = store();
    let m = file(&s, &[1, 2]);
    let c1 = commit(&s, tree_of(&s, &[("f", m)]), &[], "one");
    let c2 = commit(&s, tree_of(&s, &[("f", m), ("g", m)]), &[c1], "two");
    let seed = closure_bytes(&s, &c2);
    for new in [c1, c2] {
        let plan = plan_pack(&s, new, Some(c2)).unwrap();
        assert!(plan.is_empty(), "the remote holds {new:?}");
        assert!(!plan.self_contained);
        assert_applies(&s, &plan, &seed, new);
    }
}

#[test]
fn a_merge_whose_second_parent_is_the_remote_tip_does_not_resend_its_large_file() {
    let (_d, s) = store();
    let base = commit(
        &s,
        tree_of(&s, &[("s", put_blob(&s, b"base".to_vec()))]),
        &[],
        "base",
    );
    let big = file(&s, &[1, 2, 3, 4]);
    let remote = commit(
        &s,
        tree_of(&s, &[("big", big), ("s", put_blob(&s, b"base".to_vec()))]),
        &[base],
        "remote",
    );
    let seed = closure_bytes(&s, &remote);
    let side = commit(
        &s,
        tree_of(&s, &[("s", put_blob(&s, b"side".to_vec()))]),
        &[base],
        "side",
    );
    let merge = commit(
        &s,
        tree_of(&s, &[("big", big), ("s", put_blob(&s, b"side".to_vec()))]),
        &[side, remote],
        "merge",
    );
    let plan = plan_pack(&s, merge, Some(remote)).unwrap();
    let sent = ids(&plan);
    assert!(!sent.contains(&big));
    for k in 1..=4 {
        assert!(!sent.contains(&chunk_id(&s, k)));
    }
    assert!(sent.contains(&side) && sent.contains(&merge));
    assert_applies(&s, &plan, &seed, merge);
}

#[test]
fn renaming_a_chunked_file_sends_no_chunk() {
    let (_d, s) = store();
    let m = file(&s, &[1, 2, 3]);
    let remote = commit(&s, tree_of(&s, &[("a", m)]), &[], "remote");
    let seed = closure_bytes(&s, &remote);
    let t = tree_of(&s, &[("b", m)]);
    let new = commit(&s, t, &[remote], "rename");
    let plan = plan_pack(&s, new, Some(remote)).unwrap();
    assert_eq!(ids(&plan), BTreeSet::from([new, t]));
    assert_applies(&s, &plan, &seed, new);
}

#[test]
fn an_in_place_edit_sends_only_the_changed_chunks() {
    let (_d, s) = store();
    let v1 = big_buffer();
    let m1 = put_chunked(&s, &v1);
    let remote = commit(&s, tree_of(&s, &[("big.bin", m1)]), &[], "v1");
    let seed = closure_bytes(&s, &remote);
    let mut v2 = v1.clone();
    for k in 0..16 {
        v2[900_000 + k] ^= 0xFF;
    }
    let m2 = put_chunked(&s, &v2);
    let new = commit(&s, tree_of(&s, &[("big.bin", m2)]), &[remote], "v2");
    let before: HashSet<Hash> = manifest_chunks(&s, &m1).into_iter().collect();
    let changed: BTreeSet<Hash> = manifest_chunks(&s, &m2)
        .into_iter()
        .filter(|c| !before.contains(c))
        .collect();
    assert!(!changed.is_empty());
    let plan = plan_pack(&s, new, Some(remote)).unwrap();
    let sent = ids(&plan);
    for chunk in manifest_chunks(&s, &m2) {
        assert_eq!(sent.contains(&chunk), changed.contains(&chunk));
    }
    assert!(
        !plan.deltas.is_empty(),
        "the edited chunk travels as a delta"
    );
    assert_pack_reconstructs(&s, &plan, remote, new);
    assert_applies(&s, &plan, &seed, new);
}

#[test]
fn a_chunk_whose_delta_encode_returns_nothing_is_still_sent_raw() {
    let (_d, s) = store();
    let v1 = big_buffer();
    let m1 = put_chunked(&s, &v1);
    let remote = commit(&s, tree_of(&s, &[("big.bin", m1)]), &[], "v1");
    let seed = closure_bytes(&s, &remote);
    let mut v2 = v1.clone();
    for k in 0..16 {
        v2[100_000 + k] ^= 0xFF;
        v2[1_700_000 + k] ^= 0xFF;
    }
    let m2 = put_chunked(&s, &v2);
    let new = commit(&s, tree_of(&s, &[("big.bin", m2)]), &[remote], "v2");
    let before: HashSet<Hash> = manifest_chunks(&s, &m1).into_iter().collect();
    let changed: BTreeSet<Hash> = manifest_chunks(&s, &m2)
        .into_iter()
        .filter(|c| !before.contains(c))
        .collect();
    assert!(changed.len() >= 2, "two edits change two chunks");

    // The first candidate encodes, every other one returns nothing.
    let mut drawn = 0;
    let plan = plan_pack_with(&s, new, Some(remote), |s, candidates| {
        assert!(candidates.len() >= 2);
        candidates
            .iter()
            .map(|&c| {
                drawn += 1;
                if drawn == 1 {
                    encode_delta_candidate(s, c)
                } else {
                    Ok(None)
                }
            })
            .collect()
    })
    .unwrap();
    assert_eq!(plan.deltas.len(), 1);
    assert_eq!(ids(&plan).intersection(&changed).count(), changed.len());
    assert_applies(&s, &plan, &seed, new);

    // Nothing encodes: every changed chunk is raw.
    let plan = plan_pack_with(&s, new, Some(remote), |_, candidates| {
        Ok(vec![None; candidates.len()])
    })
    .unwrap();
    assert!(plan.deltas.is_empty());
    for chunk in &changed {
        assert!(plan.raw.contains(chunk));
    }
    assert_applies(&s, &plan, &seed, new);
}

#[test]
fn a_chunk_shared_by_two_new_files_is_sent_once() {
    let (_d, s) = store();
    let a = file(&s, &[1, 2]);
    let b = file(&s, &[2, 3]);
    let c = commit(&s, tree_of(&s, &[("a", a), ("b", b)]), &[], "two files");
    let plan = plan_pack(&s, c, None).unwrap();
    let shared = chunk_id(&s, 2);
    assert_eq!(plan.raw.iter().filter(|h| **h == shared).count(), 1);
    assert_eq!(ids(&plan), reachable_objects(&s, &c).unwrap());
    assert_eq!(plan.object_count(), 1 + 1 + 2 + 3);
    assert_applies(&s, &plan, &[], c);
}

#[test]
fn a_chunk_repeated_a_thousand_times_in_a_file_is_sent_once() {
    let (_d, s) = store();
    let m = file(&s, &vec![9; 1000]);
    let c = commit(&s, tree_of(&s, &[("f", m)]), &[], "repeat");
    let plan = plan_pack(&s, c, None).unwrap();
    assert_eq!(plan.object_count(), 4);
    assert_applies(&s, &plan, &[], c);
}

#[test]
fn an_entry_that_changes_type_at_a_path_is_sent() {
    let (_d, s) = store();
    // A file becomes a directory.
    let blob = put_blob(&s, b"file".to_vec());
    let remote = commit(&s, tree_of(&s, &[("x", blob)]), &[], "file");
    let seed = closure_bytes(&s, &remote);
    let inner = put_blob(&s, b"inner".to_vec());
    let dir = tree_of(&s, &[("y", inner)]);
    let t = tree_of(&s, &[("x", dir)]);
    let new = commit(&s, t, &[remote], "dir");
    let plan = plan_pack(&s, new, Some(remote)).unwrap();
    assert_eq!(ids(&plan), BTreeSet::from([new, t, dir, inner]));
    assert_applies(&s, &plan, &seed, new);

    // A directory becomes a file, then a chunked file.
    let seed = closure_bytes(&s, &new);
    let back = put_blob(&s, b"back".to_vec());
    let t2 = tree_of(&s, &[("x", back)]);
    let next = commit(&s, t2, &[new], "file again");
    let plan = plan_pack(&s, next, Some(new)).unwrap();
    assert_eq!(ids(&plan), BTreeSet::from([next, t2, back]));
    assert_applies(&s, &plan, &seed, next);

    let seed = closure_bytes(&s, &new);
    let m = file(&s, &[1, 2]);
    let t3 = tree_of(&s, &[("x", m)]);
    let chunked = commit(&s, t3, &[new], "chunked");
    let plan = plan_pack(&s, chunked, Some(new)).unwrap();
    assert!(ids(&plan).contains(&m));
    assert!(ids(&plan).contains(&chunk_id(&s, 1)));
    assert_applies(&s, &plan, &seed, chunked);
}

#[test]
fn a_remix_tip_is_walked_like_a_commit_and_never_through_its_sources() {
    let (_d, s) = store();
    let m1 = file(&s, &[1, 2]);
    let c1 = commit(&s, tree_of(&s, &[("f", m1)]), &[], "one");
    let seed = closure_bytes(&s, &c1);
    let m2 = file(&s, &[3]);
    let t = tree_of(&s, &[("f", m1), ("g", m2)]);
    let remix = put(
        &s,
        &Object::Remix(Remix {
            tree_hash: t,
            parents: vec![c1],
            sources: vec![RemixSource {
                upstream_id: [1; 32],
                commit_hash: [2; 32],
            }],
            author: Identity::ed25519([7; 32]),
            signer: [0; 32],
            message: b"remix".to_vec(),
            timestamp: 5,
            signature: [0; 64],
        }),
    );
    let plan = plan_pack(&s, remix, Some(c1)).unwrap();
    assert_eq!(ids(&plan), BTreeSet::from([remix, t, m2, chunk_id(&s, 3)]));
    assert_applies(&s, &plan, &seed, remix);

    // A remix on the remote side is held like a commit.
    let child = commit(&s, tree_of(&s, &[("f", m1)]), &[remix], "child");
    let seed = closure_bytes(&s, &remix);
    let plan = plan_pack(&s, child, Some(remix)).unwrap();
    assert!(ids(&plan).contains(&child));
    assert!(!ids(&plan).contains(&remix));
    assert_applies(&s, &plan, &seed, child);
}

#[test]
fn a_new_remix_is_compared_with_its_parents_like_a_commit() {
    let (_d, s) = store();
    let older_only = put_blob(&s, b"only in the older history".to_vec());
    let in_remote = put_blob(&s, b"in the remote".to_vec());
    let fresh = put_blob(&s, b"new".to_vec());
    let older = commit(&s, tree_of(&s, &[("a", older_only)]), &[], "old");
    let remote = commit(&s, tree_of(&s, &[("b", in_remote)]), &[older], "remote");
    let seed = closure_bytes(&s, &remote);
    let tree = tree_of(&s, &[("a", older_only), ("b", in_remote), ("c", fresh)]);
    let remix = put(
        &s,
        &Object::Remix(Remix {
            tree_hash: tree,
            parents: vec![older, remote],
            sources: vec![RemixSource {
                upstream_id: [1; 32],
                commit_hash: [2; 32],
            }],
            author: Identity::ed25519([7; 32]),
            signer: [0; 32],
            message: b"remix".to_vec(),
            timestamp: 5,
            signature: [0; 64],
        }),
    );
    // A commit on top of the remix names it as a new parent.
    let child = commit(
        &s,
        tree_of(&s, &[("a", older_only), ("b", in_remote), ("c", fresh)]),
        &[remix],
        "child",
    );
    let plan = plan_pack(&s, child, Some(remote)).unwrap();
    assert_eq!(ids(&plan), BTreeSet::from([remix, tree, fresh, child]));
    assert_applies(&s, &plan, &seed, child);
}

#[test]
fn a_tag_tip_plans_the_closure_of_its_target() {
    let (_d, s) = store();
    let m1 = file(&s, &[1, 2]);
    let c1 = commit(&s, tree_of(&s, &[("f", m1)]), &[], "one");
    let seed = closure_bytes(&s, &c1);
    let m2 = file(&s, &[3]);
    let c2 = commit(&s, tree_of(&s, &[("f", m1), ("g", m2)]), &[c1], "two");
    let tag = put(
        &s,
        &Object::Tag(Tag {
            target: c2,
            target_type: ObjectType::Commit,
            name: b"v1".to_vec(),
            tagger: Identity::ed25519([7; 32]),
            signer: [0; 32],
            message: b"tag".to_vec(),
            timestamp: 1,
            signature: [0; 64],
        }),
    );
    let plan = plan_pack(&s, tag, None).unwrap();
    assert!(plan.self_contained);
    assert_eq!(ids(&plan), reachable_objects(&s, &tag).unwrap());
    assert_applies(&s, &plan, &[], tag);

    let plan = plan_pack(&s, tag, Some(c1)).unwrap();
    let sent = ids(&plan);
    assert!(sent.contains(&tag) && sent.contains(&c2) && sent.contains(&m2));
    assert!(!sent.contains(&c1), "the remote holds the old commit");
    assert!(!sent.contains(&m1), "and its snapshot");
    assert_applies(&s, &plan, &seed, tag);
}

fn wide_file(s: &ObjectStore, chunks: usize) -> Hash {
    let ids: Vec<Hash> = (0..chunks)
        .map(|i| {
            let [low, high] = u16::try_from(i).expect("a small test file").to_le_bytes();
            put_blob(s, vec![low, high, 7, 7])
        })
        .collect();
    put(
        s,
        &Object::ChunkedBlob(ChunkedBlob {
            total_size: (chunks * 4) as u64,
            chunk_size: 0,
            chunks: ids,
        }),
    )
}

#[test]
fn the_cap_counts_objects_but_no_chunk() {
    let (_d, s) = store();
    let m = wide_file(&s, 2000);
    let c = commit(&s, tree_of(&s, &[("f", m)]), &[], "wide");
    // The commit, its tree and the manifest: three, whatever the chunks.
    let plan = plan_pack_capped(&s, c, None, sequential, limits(3)).unwrap();
    assert_eq!(plan.object_count(), 3 + 2000);
    assert!(matches!(
        plan_pack_capped(&s, c, None, sequential, limits(2)),
        Err(StoreError::OperationLimitExceeded(PUSH_WALK_LIMIT))
    ));
}

#[test]
fn the_cap_counts_held_commits_too_and_every_path_fails() {
    let (_d, s) = store();
    let b = put_blob(&s, b"x".to_vec());
    let t0 = tree_of(&s, &[("f", b)]);
    let c1 = commit(&s, t0, &[], "1");
    let c2 = commit(&s, t0, &[c1], "22");
    let c3 = commit(&s, t0, &[c2], "333");
    let b2 = put_blob(&s, b"y".to_vec());
    let t1 = tree_of(&s, &[("f", b2)]);
    let new = commit(&s, t1, &[c3], "new");
    // Three held commits, then the new commit, its tree and its blob.
    plan_pack_capped(&s, new, Some(c3), sequential, limits(6)).unwrap();
    for cap in [5, 3, 2, 0] {
        assert!(
            matches!(
                plan_pack_capped(&s, new, Some(c3), sequential, limits(cap)),
                Err(StoreError::OperationLimitExceeded(PUSH_WALK_LIMIT))
            ),
            "cap {cap}"
        );
    }
    // The held set alone passes at three and fails at two.
    HeldCommits::collect(&s, Some(c3), 3).unwrap();
    assert!(HeldCommits::collect(&s, Some(c3), 2).is_err());
    assert!(HeldCommits::collect(&s, Some(c3), 0).is_err());
}

#[test]
fn a_walk_of_only_commits_fits_a_cap_equal_to_its_count() {
    let (_d, s) = store();
    let t = tree_of(&s, &[("f", put_blob(&s, b"x".to_vec()))]);
    let held = commit(&s, t, &[], "held");
    let c1 = commit(&s, t, &[held], "c1");
    let c2 = commit(&s, t, &[c1], "c2");
    // One held commit and two new ones, and no tree or blob is new.
    let plan = plan_pack_capped(&s, c2, Some(held), sequential, limits(3)).unwrap();
    assert_eq!(ids(&plan), BTreeSet::from([c1, c2]));
    assert!(matches!(
        plan_pack_capped(&s, c2, Some(held), sequential, limits(2)),
        Err(StoreError::OperationLimitExceeded(PUSH_WALK_LIMIT))
    ));
}

#[test]
fn a_held_set_of_one_commit_fits_a_cap_of_one_and_not_zero() {
    let (_d, s) = store();
    let t = tree_of(&s, &[("f", put_blob(&s, b"x".to_vec()))]);
    let only = commit(&s, t, &[], "only");
    assert_eq!(HeldCommits::collect(&s, Some(only), 1).unwrap().len(), 1);
    assert!(matches!(
        HeldCommits::collect(&s, Some(only), 0),
        Err(StoreError::OperationLimitExceeded(PUSH_WALK_LIMIT))
    ));
}

#[test]
fn the_cap_stops_the_commit_walk_before_it_reads_further_history() {
    let (_d, s) = store();
    let t = tree_of(&s, &[("f", put_blob(&s, b"x".to_vec()))]);
    let c1 = commit(&s, t, &[], "1");
    let c2 = commit(&s, t, &[c1], "22");
    let c3 = commit(&s, t, &[c2], "333");
    remove(&s, &c1);
    // Past the cap at c1, the walk fails on the cap and does not go looking
    // for the commit it cannot read.
    assert!(matches!(
        plan_pack_capped(&s, c3, None, sequential, limits(2)),
        Err(StoreError::OperationLimitExceeded(PUSH_WALK_LIMIT))
    ));
    assert!(matches!(
        plan_pack_capped(&s, c3, None, sequential, limits(3)),
        Err(StoreError::ObjectNotFound(_))
    ));
}

#[test]
fn a_parent_that_is_not_a_commit_is_its_own_root() {
    let (_d, s) = store();
    let first = put_blob(&s, b"first".to_vec());
    let second = put_blob(&s, b"second".to_vec());
    let t = tree_of(&s, &[("f", put_blob(&s, b"in the tree".to_vec()))]);
    let c = commit(&s, t, &[first, second], "odd parents");
    let mut brought = Vec::new();
    PushWalk::run(
        &s,
        c,
        &HeldCommits::default(),
        &HashSet::new(),
        WalkLimits::default(),
        Some(&mut |root, id| {
            brought.push((*root, *id));
            Ok(())
        }),
    )
    .unwrap();
    assert!(brought.contains(&(c, c)) && brought.contains(&(c, t)));
    assert!(brought.contains(&(first, first)));
    assert!(brought.contains(&(second, second)));
}

#[test]
fn no_chunk_enters_a_counted_set() {
    let (_d, s) = store();
    let a = file(&s, &[1, 2, 3]);
    let b = file(&s, &[3, 4]);
    let c1 = commit(&s, tree_of(&s, &[("a", a), ("b", b)]), &[], "one");
    let a2 = file(&s, &[1, 2, 5]);
    let c2 = commit(&s, tree_of(&s, &[("a", a2), ("b", b)]), &[c1], "two");
    let chunks: HashSet<Hash> = [a, b, a2]
        .iter()
        .flat_map(|m| manifest_chunks(&s, m))
        .collect();
    take_counted();
    plan_pack(&s, c2, Some(c1)).unwrap();
    plan_pack(&s, c2, None).unwrap();
    let counted = take_counted();
    assert!(!counted.is_empty());
    for id in counted {
        assert!(!chunks.contains(&id), "a chunk entered a counted set");
    }
}

#[test]
fn a_held_scan_of_zero_sends_more_and_still_reconstructs() {
    let (_d, s) = store();
    let m = file(&s, &[1, 2, 3]);
    let remote = commit(&s, tree_of(&s, &[("a", m)]), &[], "remote");
    let seed = closure_bytes(&s, &remote);
    let t = tree_of(&s, &[("b", m)]);
    let new = commit(&s, t, &[remote], "rename");
    let none = WalkLimits {
        held_scan: 0,
        ..WalkLimits::default()
    };
    let plan = plan_pack_capped(&s, new, Some(remote), sequential, none).unwrap();
    let sent = ids(&plan);
    assert!(sent.contains(&m) && sent.contains(&chunk_id(&s, 1)));
    assert_applies(&s, &plan, &seed, new);
    let full = plan_pack(&s, new, Some(remote)).unwrap();
    assert!(plan.object_count() > full.object_count());
}

#[test]
fn the_held_scan_reads_exactly_as_many_trees_as_its_bound() {
    let (_d, s) = store();
    let m = file(&s, &[1, 2]);
    let inner = tree_of(&s, &[("a", m)]);
    let remote = commit(&s, tree_of(&s, &[("dir", inner)]), &[], "remote");
    let seed = closure_bytes(&s, &remote);
    let moved = tree_of(&s, &[("b", m)]);
    let new = commit(&s, tree_of(&s, &[("other", moved)]), &[remote], "move");
    for (scan, found) in [(0, false), (1, false), (2, true), (3, true)] {
        let bound = WalkLimits {
            held_scan: scan,
            ..WalkLimits::default()
        };
        let plan = plan_pack_capped(&s, new, Some(remote), sequential, bound).unwrap();
        assert_eq!(!ids(&plan).contains(&m), found, "scan {scan}");
        assert_applies(&s, &plan, &seed, new);
    }
}

#[test]
fn a_chunk_memory_of_zero_repeats_a_chunk_and_the_pack_still_reconstructs() {
    let (_d, s) = store();
    let m = file(&s, &[1, 2, 1, 1]);
    let c = commit(&s, tree_of(&s, &[("f", m)]), &[], "repeat");
    let memoryless = WalkLimits {
        chunk_memory: 0,
        ..WalkLimits::default()
    };
    let plan = plan_pack_capped(&s, c, None, sequential, memoryless).unwrap();
    let one = chunk_id(&s, 1);
    assert_eq!(plan.raw.iter().filter(|h| **h == one).count(), 3);
    assert_applies(&s, &plan, &[], c);
    let bounded = WalkLimits {
        chunk_memory: 1,
        ..WalkLimits::default()
    };
    let plan = plan_pack_capped(&s, c, None, sequential, bounded).unwrap();
    assert_eq!(plan.raw.iter().filter(|h| **h == one).count(), 1);
    assert_applies(&s, &plan, &[], c);
}

#[test]
fn a_repeated_delta_target_goes_out_as_one_delta_and_no_raw_copy() {
    let (_d, s) = store();
    let base: Vec<Vec<u8>> = (0..3u8).map(|k| chunk_content(k, 4000)).collect();
    let mut edited = base[1].clone();
    edited[2000] ^= 0xFF;
    let m1 = put_chunked_from(&s, &base);
    let remote = commit(&s, tree_of(&s, &[("f", m1)]), &[], "v1");
    let seed = closure_bytes(&s, &remote);
    let m2 = put_chunked_from(&s, &[base[0].clone(), edited.clone(), edited.clone()]);
    let new = commit(&s, tree_of(&s, &[("f", m2)]), &[remote], "v2");
    let target = put_blob(&s, edited);
    let memoryless = WalkLimits {
        chunk_memory: 0,
        ..WalkLimits::default()
    };
    let plan = plan_pack_capped(&s, new, Some(remote), sequential, memoryless).unwrap();
    assert_eq!(plan.deltas.iter().filter(|d| d.target == target).count(), 1);
    assert!(!plan.raw.contains(&target));
    assert_applies(&s, &plan, &seed, new);
}

#[test]
fn a_chunk_that_is_also_a_plain_blob_in_the_tree_is_sent_once() {
    let (_d, s) = store();
    let m = file(&s, &[1, 2]);
    let same = chunk_id(&s, 1);
    let c = commit(&s, tree_of(&s, &[("copy", same), ("f", m)]), &[], "dup");
    let plan = plan_pack(&s, c, None).unwrap();
    assert_eq!(plan.raw.iter().filter(|h| **h == same).count(), 1);
    assert_eq!(ids(&plan), reachable_objects(&s, &c).unwrap());
    assert_applies(&s, &plan, &[], c);
}

#[test]
fn a_missing_held_commit_ends_its_path_and_a_missing_new_commit_fails() {
    let (_d, s) = store();
    let b = put_blob(&s, b"x".to_vec());
    let t = tree_of(&s, &[("f", b)]);
    let c1 = commit(&s, t, &[], "1");
    let c2 = commit(&s, t, &[c1], "22");
    let seed = closure_bytes(&s, &c2);
    let b2 = put_blob(&s, b"y".to_vec());
    let t2 = tree_of(&s, &[("f", b2)]);
    let c3 = commit(&s, t2, &[c2], "333");
    remove(&s, &c1);
    // The held walk names c1 and cannot read it; the plan is still exact.
    let held = HeldCommits::collect(&s, Some(c2), 100).unwrap();
    assert!(held.contains(&c2) && held.contains(&c1) && held.len() == 2);
    let plan = plan_pack(&s, c3, Some(c2)).unwrap();
    assert_eq!(ids(&plan), BTreeSet::from([c3, t2, b2]));
    assert_applies(&s, &plan, &seed, c3);

    // A new commit that cannot be read is a typed error, never a short plan.
    let new = commit(&s, t2, &[c1], "new");
    assert!(matches!(
        plan_pack(&s, new, None),
        Err(StoreError::ObjectNotFound(_))
    ));
    // So is a new tree, and a blob of a new tree.
    let lost = tree_of(&s, &[("f", put_blob(&s, b"lost".to_vec()))]);
    let c4 = commit(&s, lost, &[c2], "4444");
    remove(&s, &lost);
    assert!(matches!(
        plan_pack(&s, c4, Some(c2)),
        Err(StoreError::ObjectNotFound(_))
    ));
    let gone = put_blob(&s, b"gone".to_vec());
    let t5 = tree_of(&s, &[("f", gone)]);
    let c5 = commit(&s, t5, &[c2], "55555");
    remove(&s, &gone);
    assert!(matches!(
        plan_pack(&s, c5, Some(c2)),
        Err(StoreError::ObjectNotFound(_))
    ));
}

#[test]
fn a_parent_tree_this_store_cannot_read_prunes_nothing() {
    let (_d, s) = store();
    let keep = put_blob(&s, b"keep".to_vec());
    let t1 = tree_of(&s, &[("f", keep)]);
    let remote = commit(&s, t1, &[], "remote");
    let seed = closure_bytes(&s, &remote);
    let extra = put_blob(&s, b"extra".to_vec());
    let t2 = tree_of(&s, &[("f", keep), ("g", extra)]);
    let new = commit(&s, t2, &[remote], "new");
    remove(&s, &t1);
    let plan = plan_pack(&s, new, Some(remote)).unwrap();
    // Without the parent's tree the plan cannot tell `keep` is held.
    assert_eq!(ids(&plan), BTreeSet::from([new, t2, keep, extra]));
    assert_applies(&s, &plan, &seed, new);
}

#[test]
fn an_entry_equal_to_any_parents_entry_is_skipped() {
    let (_d, s) = store();
    let (a, b) = (put_blob(&s, b"a".to_vec()), put_blob(&s, b"b".to_vec()));
    let p1 = commit(&s, tree_of(&s, &[("f", a)]), &[], "p1");
    let p2 = commit(&s, tree_of(&s, &[("g", b)]), &[], "p2");
    let merged = tree_of(&s, &[("f", a), ("g", b)]);
    let m = commit(&s, merged, &[p1, p2], "merge");
    let walk = PushWalk::run(
        &s,
        m,
        &HeldCommits::collect(&s, Some(p1), 100).unwrap(),
        &HashSet::new(),
        WalkLimits::default(),
        None,
    )
    .unwrap();
    // Both entries are covered: `f` by the held parent, `g` by the new one.
    assert!(walk.objects().contains(&m) && walk.objects().contains(&merged));
    assert!(walk.objects().contains(&p2));
    assert!(!walk.objects().contains(&a));
    assert!(walk.objects().contains(&b), "p2 is new and sends g");
    assert_eq!(walk.objects().len(), 5, "m, merged, p2, p2's tree, b");
}

#[test]
fn a_subtree_is_compared_with_every_parents_subtree_at_its_path() {
    let (_d, s) = store();
    let a = put_blob(&s, b"only in the older history".to_vec());
    let b = put_blob(&s, b"in the remote".to_vec());
    let c = put_blob(&s, b"new".to_vec());
    let older = commit(
        &s,
        tree_of(&s, &[("d", tree_of(&s, &[("a", a)]))]),
        &[],
        "old",
    );
    let remote = commit(
        &s,
        tree_of(&s, &[("d", tree_of(&s, &[("b", b)]))]),
        &[older],
        "remote",
    );
    let merge = commit(
        &s,
        tree_of(&s, &[("d", tree_of(&s, &[("a", a), ("b", b), ("c", c)]))]),
        &[older, remote],
        "merge",
    );
    let seed = closure_bytes(&s, &remote);
    let plan = plan_pack(&s, merge, Some(remote)).unwrap();
    let sent = ids(&plan);
    assert!(!sent.contains(&a), "the older parent holds it at this path");
    assert!(!sent.contains(&b));
    assert!(sent.contains(&c) && sent.contains(&merge));
    assert_applies(&s, &plan, &seed, merge);
}

#[test]
fn a_tree_tip_drops_what_the_remote_snapshot_holds_at_another_path() {
    let (_d, s) = store();
    let held = put_blob(&s, b"the remote has this".to_vec());
    let fresh = put_blob(&s, b"fresh".to_vec());
    let remote = commit(&s, tree_of(&s, &[("old", held)]), &[], "remote");
    let seed = closure_bytes(&s, &remote);
    let tip = tree_of(&s, &[("moved", held), ("fresh", fresh)]);
    let plan = plan_pack(&s, tip, Some(remote)).unwrap();
    let sent = ids(&plan);
    assert!(!sent.contains(&held));
    assert!(sent.contains(&tip) && sent.contains(&fresh));
    assert_applies(&s, &plan, &seed, tip);
}

#[test]
fn a_tree_equal_to_a_parents_tree_keeps_only_the_commit() {
    let (_d, s) = store();
    let a = put_blob(&s, b"a".to_vec());
    let t = tree_of(&s, &[("f", a)]);
    let c1 = commit(&s, t, &[], "1");
    let c2 = commit(&s, t, &[c1], "22");
    let held = HeldCommits::collect(&s, Some(c1), 100).unwrap();
    let walk = PushWalk::run(&s, c2, &held, &HashSet::new(), WalkLimits::default(), None).unwrap();
    assert_eq!(walk.objects(), &BTreeSet::from([c2]));
    assert!(walk.manifests().is_empty());
}

#[test]
fn a_wide_tree_keeps_only_the_entries_that_changed() {
    let (_d, s) = store();
    let blobs: Vec<Hash> = (0..9u8).map(|k| put_blob(&s, vec![k; 8])).collect();
    let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
    let before: Vec<(&str, Hash)> = names.iter().copied().zip(blobs.iter().copied()).collect();
    let c1 = commit(&s, tree_of(&s, &before), &[], "1");
    let edited = put_blob(&s, b"edited".to_vec());
    for index in 0..9 {
        let mut after = before.clone();
        after[index].1 = edited;
        let t = tree_of(&s, &after);
        let c2 = commit(&s, t, &[c1], &format!("edit {index}"));
        let held = HeldCommits::collect(&s, Some(c1), 100).unwrap();
        let walk =
            PushWalk::run(&s, c2, &held, &HashSet::new(), WalkLimits::default(), None).unwrap();
        assert_eq!(walk.objects(), &BTreeSet::from([c2, t, edited]), "{index}");
    }
}

#[test]
fn a_manifest_is_paired_with_the_manifest_at_its_path_in_a_parent() {
    let (_d, s) = store();
    let (m1, m2, m3) = (file(&s, &[1, 2]), file(&s, &[1, 3]), file(&s, &[1, 4]));
    let dir = tree_of(&s, &[("x", put_blob(&s, b"x".to_vec()))]);
    // The first parent has a directory at `f`; the second has the manifest.
    let p1 = commit(&s, tree_of(&s, &[("f", dir)]), &[], "p1");
    let p2 = commit(&s, tree_of(&s, &[("f", m1)]), &[], "p2");
    let t = tree_of(&s, &[("f", m2)]);
    let merge = commit(&s, t, &[p1, p2], "merge");
    let held = HeldCommits::collect(&s, Some(p1), 100).unwrap();
    let walk = PushWalk::run(
        &s,
        merge,
        &held,
        &HashSet::new(),
        WalkLimits::default(),
        None,
    )
    .unwrap();
    let paired: Vec<_> = walk
        .manifests()
        .iter()
        .map(|m| (m.id, m.old, m.commit))
        .collect();
    assert!(paired.contains(&(m2, Some(m1), merge)));
    assert!(paired.contains(&(m1, None, p2)));

    // The chunks the old manifest lists are not listed again.
    let mut sent = Vec::new();
    walk.for_each_chunk(&s, &mut ChunkMemory::new(100), |_, chunk| {
        sent.push(chunk);
        Ok(())
    })
    .unwrap();
    assert_eq!(sent.iter().filter(|c| **c == chunk_id(&s, 1)).count(), 1);
    assert!(sent.contains(&chunk_id(&s, 3)));
    let _ = m3;
}

#[test]
fn held_commits_are_the_exact_ancestors_with_the_tip() {
    let (_d, s) = store();
    let t = tree_of(&s, &[("f", put_blob(&s, b"x".to_vec()))]);
    let root = commit(&s, t, &[], "root");
    let left = commit(&s, t, &[root], "left");
    let right = commit(&s, t, &[root], "right!");
    let merge = commit(&s, t, &[left, right], "merge");
    let stray = commit(&s, t, &[], "stray");
    let held = HeldCommits::collect(&s, Some(merge), 100).unwrap();
    assert_eq!(held.len(), 4);
    assert!(!held.is_empty());
    assert_eq!(held.tip(), Some(merge));
    for id in [root, left, right, merge] {
        assert!(held.contains(&id));
    }
    assert!(!held.contains(&stray));
    assert!(HeldCommits::collect(&s, None, 100).unwrap().is_empty());
    let absent = HeldCommits::collect(&s, Some([9; 32]), 100).unwrap();
    assert!(absent.is_empty() && absent.tip().is_none());
}

#[test]
fn new_commits_are_walked_parents_first_and_once() {
    let (_d, s) = store();
    let one = put_blob(&s, b"1".to_vec());
    let root = commit(&s, tree_of(&s, &[("f", one)]), &[], "root");
    let mut brought = Vec::new();
    let a = put_blob(&s, b"a".to_vec());
    let left = commit(&s, tree_of(&s, &[("l", a)]), &[root], "left");
    let right = commit(&s, tree_of(&s, &[("r", a)]), &[root], "right!");
    let merge = commit(
        &s,
        tree_of(&s, &[("l", a), ("r", a)]),
        &[left, right],
        "merge",
    );
    PushWalk::run(
        &s,
        merge,
        &HeldCommits::default(),
        &HashSet::new(),
        WalkLimits::default(),
        Some(&mut |commit, id| {
            if commit == id {
                brought.push(*id);
            }
            Ok(())
        }),
    )
    .unwrap();
    assert_eq!(brought.len(), 4);
    let at = |h: &Hash| brought.iter().position(|x| x == h).unwrap();
    assert!(at(&root) < at(&left) && at(&root) < at(&right));
    assert!(at(&left) < at(&merge) && at(&right) < at(&merge));
}

#[test]
fn a_shallow_commit_is_a_root() {
    let (_d, s) = store();
    let t = tree_of(&s, &[("f", put_blob(&s, b"x".to_vec()))]);
    let old = commit(&s, t, &[], "old");
    let boundary = commit(&s, t, &[old], "boundary");
    remove(&s, &old);
    let walk = PushWalk::run(
        &s,
        boundary,
        &HeldCommits::default(),
        &HashSet::from([boundary]),
        WalkLimits::default(),
        None,
    )
    .unwrap();
    assert!(walk.objects().contains(&boundary));
    assert!(matches!(
        PushWalk::run(
            &s,
            boundary,
            &HeldCommits::default(),
            &HashSet::new(),
            WalkLimits::default(),
            None,
        ),
        Err(StoreError::ObjectNotFound(_))
    ));
}

#[test]
fn a_manifest_that_lists_a_non_blob_is_a_typed_error() {
    let (_d, s) = store();
    let tree = tree_of(&s, &[]);
    let m = put(
        &s,
        &Object::ChunkedBlob(ChunkedBlob {
            total_size: 1,
            chunk_size: 0,
            chunks: vec![tree],
        }),
    );
    let c = commit(&s, tree_of(&s, &[("f", m)]), &[], "bad");
    assert!(matches!(
        plan_pack(&s, c, None),
        Err(StoreError::Decode(KitError::InvalidObjectType(0x02)))
    ));
}

#[test]
fn an_object_that_only_a_tree_names_is_kept_once_for_every_path() {
    let (_d, s) = store();
    let blob = put_blob(&s, b"same".to_vec());
    let sub = tree_of(&s, &[("f", blob)]);
    let t = tree_of(&s, &[("a", sub), ("b", sub), ("c", blob)]);
    let c = commit(&s, t, &[], "dup");
    let plan = plan_pack(&s, c, None).unwrap();
    assert_eq!(plan.object_count(), 4);
    assert_eq!(ids(&plan), reachable_objects(&s, &c).unwrap());
}

// ---------------------------------------------------------------------
// Property test against the closure difference the plan replaced.
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Slot {
    Absent,
    Small(u8),
    Big(u8),
    Dir(u8),
    Same,
}

#[derive(Debug, Clone)]
struct CommitSpec {
    parents: Vec<u8>,
    slots: Vec<Slot>,
}

#[derive(Debug, Clone)]
enum RemoteSpec {
    None,
    Commit(u8),
    Unrelated(Vec<CommitSpec>),
}

fn slot() -> impl Strategy<Value = Slot> {
    prop_oneof![
        Just(Slot::Absent),
        (0u8..4).prop_map(Slot::Small),
        (0u8..5).prop_map(Slot::Big),
        (0u8..3).prop_map(Slot::Dir),
        Just(Slot::Same),
        Just(Slot::Same),
    ]
}

fn commit_spec() -> impl Strategy<Value = CommitSpec> {
    (
        prop::collection::vec(0u8..12, 0..3),
        prop::collection::vec(slot(), 3),
    )
        .prop_map(|(parents, slots)| CommitSpec { parents, slots })
}

fn remote_spec() -> impl Strategy<Value = RemoteSpec> {
    prop_oneof![
        Just(RemoteSpec::None),
        (0u8..12).prop_map(RemoteSpec::Commit),
        prop::collection::vec(commit_spec(), 1..4).prop_map(RemoteSpec::Unrelated),
    ]
}

const NAMES: [&str; 3] = ["a", "b", "d"];

/// Chunk contents: a shared pool whose last member is a near copy of the first,
/// so edits can travel as deltas.
fn pool_chunk(s: &ObjectStore, k: u8) -> Hash {
    let mut content = chunk_content(k % 6, 600);
    if k == 6 {
        content[300] ^= 0xFF;
    }
    put_blob(s, content)
}

fn pool_big(s: &ObjectStore, k: u8) -> Hash {
    let lists: [&[u8]; 5] = [&[0, 1, 2], &[6, 1, 2], &[4, 4, 4, 4], &[1, 2], &[0, 1, 3]];
    let chunks: Vec<Hash> = lists[usize::from(k) % 5]
        .iter()
        .map(|&c| pool_chunk(s, c))
        .collect();
    put(
        s,
        &Object::ChunkedBlob(ChunkedBlob {
            total_size: chunks.len() as u64 * 600,
            chunk_size: 0,
            chunks,
        }),
    )
}

fn pool_small(s: &ObjectStore, k: u8) -> Hash {
    let content = match k % 4 {
        0 => chunk_content(20, 300),
        1 => {
            let mut c = chunk_content(20, 300);
            c[100] ^= 0xFF;
            c
        }
        // A blob that is also a chunk of the pool.
        2 => chunk_content(1, 600),
        _ => b"tiny".to_vec(),
    };
    put_blob(s, content)
}

fn pool_dir(s: &ObjectStore, k: u8) -> Hash {
    match k % 3 {
        0 => tree_of(s, &[("x", pool_small(s, 0))]),
        1 => tree_of(s, &[("x", pool_big(s, 1)), ("y", pool_small(s, 1))]),
        _ => tree_of(s, &[("y", pool_big(s, 0))]),
    }
}

fn build(s: &ObjectStore, specs: &[CommitSpec], tag: &str) -> Vec<Hash> {
    let mut made: Vec<Hash> = Vec::new();
    let mut entries: Vec<Vec<Option<Hash>>> = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        let mut parents: Vec<usize> = Vec::new();
        if i > 0 {
            for p in &spec.parents {
                let p = usize::from(*p) % i;
                if !parents.contains(&p) {
                    parents.push(p);
                }
            }
        }
        let mut row: Vec<Option<Hash>> = Vec::new();
        for (n, slot) in spec.slots.iter().enumerate() {
            row.push(match slot {
                Slot::Absent => None,
                Slot::Small(k) => Some(pool_small(s, *k)),
                Slot::Big(k) => Some(pool_big(s, *k)),
                Slot::Dir(k) => Some(pool_dir(s, *k)),
                Slot::Same => parents.first().and_then(|p| entries[*p][n]),
            });
        }
        let listed: Vec<(&str, Hash)> = NAMES
            .iter()
            .copied()
            .zip(row.iter())
            .filter_map(|(name, h)| h.map(|h| (name, h)))
            .collect();
        let tree = tree_of(s, &listed);
        let parent_ids: Vec<Hash> = parents.iter().map(|p| made[*p]).collect();
        made.push(commit(s, tree, &parent_ids, &format!("{tag}-{i}")));
        entries.push(row);
    }
    made
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn the_plan_holds_everything_the_closure_difference_holds(
        specs in prop::collection::vec(commit_spec(), 1..=12),
        tip in 0u8..12,
        remote in remote_spec(),
    ) {
        let (_d, s) = store();
        let made = build(&s, &specs, "main");
        let new = made[usize::from(tip) % made.len()];
        let remote_tip = match &remote {
            RemoteSpec::None => None,
            RemoteSpec::Commit(k) => Some(made[usize::from(*k) % made.len()]),
            RemoteSpec::Unrelated(other) => build(&s, other, "other").last().copied(),
        };

        // Today's answer: the closure of the new tip less the remote's.
        let new_closure = reachable_objects(&s, &new).unwrap();
        let remote_closure = remote_tip.map(|r| reachable_objects(&s, &r).unwrap());
        let old_answer: BTreeSet<Hash> = match &remote_closure {
            Some(held) => new_closure.difference(held).copied().collect(),
            None => new_closure.clone(),
        };

        let plan = plan_pack(&s, new, remote_tip).unwrap();
        let sent = ids(&plan);
        prop_assert!(
            old_answer.is_subset(&sent),
            "the plan omits {:?}",
            old_answer.difference(&sent).count()
        );
        prop_assert!(sent.is_subset(&new_closure), "the plan sends an object outside the closure");

        let seed: Vec<(Hash, Vec<u8>)> = remote_closure
            .iter()
            .flatten()
            .map(|h| (*h, s.read(h).unwrap()))
            .collect();
        assert_applies(&s, &plan, &seed, new);

        // The same holds when the held scan reads nothing.
        let blind = plan_pack_capped(
            &s,
            new,
            remote_tip,
            sequential,
            WalkLimits { held_scan: 0, ..WalkLimits::default() },
        )
        .unwrap();
        prop_assert!(old_answer.is_subset(&ids(&blind)));
        assert_applies(&s, &blind, &seed, new);
    }
}
