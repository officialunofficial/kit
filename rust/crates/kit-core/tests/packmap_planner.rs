//! Frozen decision projections from the former CLI and client push loops.
//! Chain walking, failure classification, reset authorization, and conflict I/O
//! stay in those drivers: notably, their depth/count errors differ.
#![allow(clippy::unwrap_used)]

use std::collections::HashSet;

use kit_core::{
    hash::{Hash, to_hex},
    pack::pack_key,
    refs::RefWriteCondition,
    transfer::{
        encode_packlist,
        packmap::{ChainState, Node, PlanError, plan_advance},
    },
};
use proptest::prelude::*;

#[test]
#[allow(clippy::too_many_lines)] // Keep capture rendering and boundary checks together.
fn planner_matches_recorded_driver_matrix() {
    use kit_core::{
        hash::hash,
        object::{Blob, Object},
        pack::PackWriter,
        serialize::serialize,
    };
    use std::fmt::Write as _;

    // Both real-driver capture tests use these canonical, sub-64-byte blobs.
    // The payload cap seals one blob per pack, so recreate those packs directly.
    let keys: Vec<Hash> = [1_u8, 2]
        .into_iter()
        .map(|salt| {
            let bytes = serialize(&Object::Blob(Blob {
                data: vec![salt; 10],
            }))
            .unwrap();
            let mut writer = PackWriter::new();
            writer.push_raw(hash(&bytes), &bytes).unwrap();
            pack_key(&writer.finish().unwrap())
        })
        .collect();
    let mut output = String::new();
    writeln!(
        output,
        "capture packs {} {}",
        to_hex(&keys[0]),
        to_hex(&keys[1])
    )
    .unwrap();
    for (label, held, reset, conflict) in [
        ("first", None, false, false),
        ("append", Some(vec![[9; 32]]), false, false),
        ("partial", Some(vec![keys[0]]), false, false),
        ("full", Some(keys.clone()), false, false),
        ("rollover", Some(keys.clone()), true, false),
        ("changed-prior", Some(vec![[9; 32]]), false, true),
    ] {
        let prior = held
            .as_ref()
            .map(|packs| pack_key(&encode_packlist(None, packs).unwrap()));
        let retry = prior.map(|head| pack_key(&encode_packlist(Some(head), &[[8; 32]]).unwrap()));
        for attempt in 0..if conflict { 2 } else { 1 } {
            let current = if attempt == 0 { prior } else { retry };
            let mut held_set: HashSet<Hash> =
                held.clone().unwrap_or_default().into_iter().collect();
            if attempt > 0 {
                held_set.insert([8; 32]);
            }
            let planned = plan_advance(state(current, &held_set, reset), &keys, None).unwrap();
            let Some(node) = planned else {
                assert_eq!(label, "full");
                writeln!(
                    output,
                    "capture {label} prior={} head-only",
                    to_hex(&current.unwrap())
                )
                .unwrap();
                continue;
            };
            let length = u64::try_from(node.bytes.len()).unwrap();
            assert_eq!(
                plan_advance(state(current, &held_set, reset), &keys, Some(length - 1)),
                Err(PlanError::NodeTooLarge)
            );
            assert_eq!(
                plan_advance(state(current, &held_set, reset), &keys, Some(length)),
                Ok(Some(Node {
                    bytes: node.bytes.clone(),
                    key: node.key,
                    condition: node.condition
                }))
            );
            assert_eq!(
                node.condition,
                current.map_or(RefWriteCondition::Missing, RefWriteCondition::Match)
            );
            writeln!(
                output,
                "capture {label} attempt={attempt} prior={} node={} cas={}",
                current.as_ref().map_or_else(|| "missing".into(), to_hex),
                to_hex(&node.key),
                if current.is_some() {
                    "match"
                } else {
                    "missing"
                }
            )
            .unwrap();
        }
    }
    assert_eq!(output, include_str!("fixtures/packmap_advance.txt"));
}

// These retain the old pure decisions, rather than invoking the new planner.
// `reset` represents either an authorized rollover or a classified broken chain.
fn former_cli(prior: Option<Hash>, held: &[Hash], keys: &[Hash], reset: bool) -> Option<Node> {
    let prev = if reset {
        None
    } else if let Some(head) = prior {
        let have: HashSet<&Hash> = held.iter().collect();
        if keys.iter().all(|key| have.contains(key)) {
            return None;
        }
        Some(head)
    } else {
        None
    };
    let bytes = encode_packlist(prev, keys).unwrap();
    Some(Node {
        key: pack_key(&bytes),
        bytes,
        condition: prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
    })
}

fn former_client(
    prior: Option<Hash>,
    held: &[Hash],
    keys: &[Hash],
    reset: bool,
    cap: u64,
) -> Result<Option<Node>, PlanError> {
    let packs: HashSet<Hash> = held.iter().copied().collect();
    let prev = match (reset, prior) {
        (true, _) | (false, None) => None,
        (false, Some(_)) if keys.iter().all(|key| packs.contains(key)) => return Ok(None),
        (false, Some(root)) => Some(root),
    };
    let bytes = encode_packlist(prev, keys)?;
    if bytes.len() as u64 > cap {
        return Err(PlanError::NodeTooLarge);
    }
    Ok(Some(Node {
        key: pack_key(&bytes),
        bytes,
        condition: prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
    }))
}

fn state(prior: Option<Hash>, held: &HashSet<Hash>, reset: bool) -> ChainState {
    if reset {
        ChainState::Reset { prior }
    } else {
        prior.map_or(ChainState::Missing, |head| ChainState::Append {
            head,
            packs: held.clone(),
        })
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep fixture cases and their assertions together.
fn former_driver_fixture_matrix_matches_literal_wire_and_ids() {
    let (a, b, c, retry_head) = ([0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]);
    // Expected ids are independently derived from the existing pinned KPKL
    // codec layout, not claimed to be captures of former driver executions.
    let fixtures = [
        (
            "first",
            None,
            vec![],
            vec![b],
            false,
            Some("8460aaeab2f0794e13e56799e56fafe15861ee87fac489bcd976ef92c6865d35"),
        ),
        (
            "append",
            Some(a),
            vec![c],
            vec![b],
            false,
            Some("3befb2598f86b347f4b20c0d160962da2411321dfc37b7606d06561d68c38bbd"),
        ),
        (
            "partial overlap",
            Some(a),
            vec![b],
            vec![b, c],
            false,
            Some("1a81a692a6910ef19b04fd894bf304c90201d3d8d46a2fcd8f52e936bca8bf69"),
        ),
        (
            "full overlap retry",
            Some(a),
            vec![c, b],
            vec![b, c],
            false,
            None,
        ),
        (
            "rollover",
            Some(a),
            vec![b, c],
            vec![b, c],
            true,
            Some("cf106b92ed63094c1e789ca404c533e11a7543930d1123bfd9aa07dbb6bbd9c8"),
        ),
        (
            "changed head retry",
            Some(retry_head),
            vec![b],
            vec![b, c],
            false,
            Some("1fadd223798f466a638ceb05f4e8cd36dd1780cc26db1e590466e01040b63ac7"),
        ),
        (
            "reset retry",
            Some(retry_head),
            vec![b, c],
            vec![b, c],
            true,
            Some("cf106b92ed63094c1e789ca404c533e11a7543930d1123bfd9aa07dbb6bbd9c8"),
        ),
        (
            "broken chain reset",
            Some(a),
            vec![],
            vec![b, c],
            true,
            Some("cf106b92ed63094c1e789ca404c533e11a7543930d1123bfd9aa07dbb6bbd9c8"),
        ),
    ];
    for (label, prior, held, keys, reset, expected_id) in fixtures {
        let held_set = held.iter().copied().collect();
        let planned = plan_advance(state(prior, &held_set, reset), &keys, None).unwrap();
        assert_eq!(
            planned,
            former_cli(prior, &held, &keys, reset),
            "{label}: CLI"
        );
        assert_eq!(
            Ok(planned.as_ref()),
            former_client(prior, &held, &keys, reset, u64::MAX)
                .as_ref()
                .map(Option::as_ref),
            "{label}: client"
        );
        assert_eq!(
            planned.as_ref().map(|node| to_hex(&node.key)),
            expected_id.map(str::to_owned),
            "{label}"
        );
        if let Some(node) = planned {
            // Independent literal encoding for this fixture's one-byte counts.
            let mut wire = b"KPKL\x01".to_vec();
            match prior.filter(|_| !reset) {
                Some(head) => {
                    wire.push(1);
                    wire.extend_from_slice(&head);
                }
                None => wire.push(0),
            }
            wire.push(u8::try_from(keys.len()).unwrap());
            for key in &keys {
                wire.extend_from_slice(key);
            }
            assert_eq!(node.bytes, wire, "{label}: wire");
            assert_eq!(
                node.condition,
                prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match)
            );
            let length = u64::try_from(node.bytes.len()).unwrap();
            assert_eq!(
                plan_advance(state(prior, &held_set, reset), &keys, Some(length - 1)),
                Err(PlanError::NodeTooLarge),
                "{label}: under-size cap"
            );
            assert_eq!(
                plan_advance(state(prior, &held_set, reset), &keys, Some(length)),
                Ok(Some(node)),
                "{label}: exact-size cap"
            );
            for cap in [length - 1, length] {
                assert_eq!(
                    plan_advance(state(prior, &held_set, reset), &keys, Some(cap)),
                    former_client(prior, &held, &keys, reset, cap),
                    "{label}: byte boundary"
                );
            }
        }
    }
}

proptest! {
    #[test]
    fn arbitrary_retry_inputs_match_both_former_drivers(
        prior in proptest::option::of(any::<[u8; 32]>()),
        held_seeds in prop::collection::vec(0_u8..8, 0..32),
        key_seeds in prop::collection::vec(0_u8..8, 1..32),
        reset in any::<bool>(),
        cap in 0_u64..1200,
    ) {
        let held: Vec<Hash> = held_seeds.iter().map(|seed| [*seed; 32]).collect();
        let keys: Vec<Hash> = key_seeds.iter().map(|seed| [*seed; 32]).collect();
        let held_set = held.iter().copied().collect();
        prop_assert_eq!(
            plan_advance(state(prior, &held_set, reset), &keys, None),
            Ok(former_cli(prior, &held, &keys, reset)),
        );
        prop_assert_eq!(
            plan_advance(state(prior, &held_set, reset), &keys, Some(cap)),
            former_client(prior, &held, &keys, reset, cap),
        );
    }
}

#[test]
fn codec_entry_cap_and_idempotent_short_circuit_are_preserved() {
    use kit_core::transfer::{PACKLIST_MAX_ENTRIES, PackListError};
    let keys = vec![[0x22; 32]; PACKLIST_MAX_ENTRIES as usize + 1];
    let expected = PlanError::Packlist(PackListError::TooManyEntries(PACKLIST_MAX_ENTRIES + 1));
    assert_eq!(
        plan_advance(ChainState::Missing, &keys, None),
        Err(expected)
    );
    let held = HashSet::from([[0x22; 32]]);
    assert_eq!(
        plan_advance(
            ChainState::Append {
                head: [0x11; 32],
                packs: held
            },
            &keys,
            Some(0)
        ),
        Ok(None)
    );
    assert_eq!(
        plan_advance(
            ChainState::Reset {
                prior: Some([0x11; 32])
            },
            &keys,
            None
        ),
        Err(PlanError::Packlist(PackListError::TooManyEntries(
            PACKLIST_MAX_ENTRIES + 1
        )))
    );
}

#[test]
fn a_rollover_lists_the_chain_then_each_new_pack_it_lacks() {
    let head = [0x11; 32];
    let chain = vec![[1; 32], [2; 32], [3; 32]];
    let rollover = || ChainState::Rollover {
        head,
        packs: chain.clone(),
    };
    // A new pack the chain already lists is not listed twice.
    let node = plan_advance(rollover(), &[[2; 32], [4; 32], [5; 32]], None)
        .unwrap()
        .unwrap();
    let listed = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
    assert_eq!(node.bytes, encode_packlist(None, &listed).unwrap());
    assert_eq!(node.key, pack_key(&node.bytes));
    assert_eq!(node.condition, RefWriteCondition::Match(head));
    // A chain that lists every new pack needs no node.
    assert_eq!(
        plan_advance(rollover(), &[[3; 32], [1; 32]], None),
        Ok(None)
    );
    // The node-size limit covers the whole listing.
    let length = node.bytes.len() as u64;
    assert_eq!(
        plan_advance(rollover(), &[[4; 32], [5; 32]], Some(length - 1)),
        Err(PlanError::NodeTooLarge)
    );
    assert!(plan_advance(rollover(), &[[4; 32], [5; 32]], Some(length)).is_ok());
}

#[test]
fn a_validated_chain_rolls_over_only_at_the_threshold_and_within_one_node() {
    use kit_core::transfer::packmap::ROLLOVER_MAX_PACKS;
    let head = [0x11; 32];
    let rolls = |depth, held: usize, new, threshold| {
        let packs = vec![[7; 32]; held];
        match ChainState::validated(head, depth, packs.clone(), new, threshold) {
            ChainState::Rollover { head: h, packs: p } => {
                assert_eq!((h, p), (head, packs));
                true
            }
            ChainState::Append { head: h, packs: p } => {
                assert_eq!(h, head);
                assert_eq!(p, packs.into_iter().collect());
                false
            }
            other => panic!("{other:?}"),
        }
    };
    assert!(!rolls(63, 63, 1, 64));
    assert!(rolls(64, 64, 1, 64));
    assert!(rolls(65, 65, 1, 64));
    assert!(rolls(1, 1, 1, 1));
    assert!(!rolls(1000, 1000, 1, 0), "zero never rolls over");
    assert!(rolls(64, ROLLOVER_MAX_PACKS - 1, 1, 64));
    assert!(!rolls(64, ROLLOVER_MAX_PACKS, 1, 64));
    assert!(!rolls(64, ROLLOVER_MAX_PACKS - 1, 2, 64));
    assert!(!rolls(64, 2, usize::MAX, 64), "the count saturates");
}

#[test]
fn a_rollover_node_of_the_most_packs_is_far_under_the_node_download_limit() {
    use kit_core::transfer::packmap::ROLLOVER_MAX_PACKS;
    const NODE_LIMIT: u64 = 1024 * 1024;
    let key = |i: usize| {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(i as u64).to_le_bytes());
        key
    };
    let chain: Vec<Hash> = (0..ROLLOVER_MAX_PACKS - 1).map(key).collect();
    let new = key(ROLLOVER_MAX_PACKS);
    let node = plan_advance(
        ChainState::Rollover {
            head: [0x11; 32],
            packs: chain,
        },
        &[new],
        Some(NODE_LIMIT),
    )
    .unwrap()
    .unwrap();
    assert_eq!(ROLLOVER_MAX_PACKS, 4096);
    assert!(
        (node.bytes.len() as u64) < NODE_LIMIT / 4,
        "{}",
        node.bytes.len()
    );
    assert_eq!(node.bytes.len(), 8 + 32 * ROLLOVER_MAX_PACKS);
}
