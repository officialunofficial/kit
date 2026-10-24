//! Pins the bytes of a fixed plan. A change to these ids means pack bytes
//! changed: restarted pushes would no longer reproduce their pack ids, so the
//! change must be called out under "Breaking" in the CHANGELOG.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)] // unwrap is the assertion in test helpers

use kit_client::{Entry, Limits, Plan};
use kit_core::{
    hash::{Hash, hash, to_hex},
    transfer::packmap::{ChainState, plan_advance},
};

/// Entries stay under 64 bytes, so no build (with or without a zstd writer)
/// compresses them: the bytes are the same for every feature set.
fn fixture() -> Vec<Entry> {
    let raw = |seed: u8, len: usize| {
        let bytes: Vec<u8> = (0..len)
            .map(|i| seed.wrapping_mul(31).wrapping_add(i as u8))
            .collect();
        Entry::Raw {
            id: hash(&bytes),
            bytes,
        }
    };
    vec![
        raw(1, 40),
        raw(2, 33),
        Entry::Delta {
            base: hash(
                &(0..40)
                    .map(|i| 1_u8.wrapping_mul(31).wrapping_add(i))
                    .collect::<Vec<u8>>(),
            ),
            stream: vec![7; 20],
        },
        raw(3, 50),
    ]
}

fn ids(limits: Limits) -> (Vec<String>, String) {
    let plan = Plan::prepare(fixture(), limits).unwrap();
    let keys: Vec<Hash> = plan.pack_ids().copied().collect();
    let node = plan_advance(ChainState::Missing, &keys, Some(limits.max_pack_bytes))
        .unwrap()
        .unwrap();
    (keys.iter().map(to_hex).collect(), to_hex(&node.key))
}

#[test]
fn one_pack_plan_ids_are_stable() {
    let (packs, node) = ids(Limits::default());
    assert_eq!(
        packs,
        ["84c3912b1d9a228a0fe46677b2ad5a54c877f7843791b37bb77786d4cbb239df"]
    );
    assert_eq!(
        node,
        "309d37790fb5cb82c80ecb96f410ec3f174dc4d2b571c298509bbcdd9b6e0d0a"
    );
}

#[test]
fn split_plan_ids_are_stable() {
    // A tight payload cap forces several packs, pinning the split points too.
    let (packs, node) = ids(Limits {
        payload_bytes: 100,
        ..Limits::default()
    });
    assert_eq!(
        packs,
        [
            "01fe04f5dfa1f86d0970df0824012029309e23ab8dd1b868593687a031f1039b",
            "eeebc0228e0750b205094c5139b42dea73a450678f9e547914be591cfd05e259",
            "bcacfb6cd375c8605a942758f58706b28bb20d3475ceaf27e35b56dfc74272b5",
        ]
    );
    assert_eq!(
        node,
        "274e8ae9f9d5ef1394bbc3fc055d06acebdce9478f9f9292b35f2e71a09d03a4"
    );
}
