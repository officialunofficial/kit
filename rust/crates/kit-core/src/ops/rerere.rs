//! The pure rules of the recorded-resolution cache (`rr-cache/`): how a
//! text conflict is named and when an entry read from disk is valid. The
//! files, the replay and the recording live in `libkit::rerere`. See
//! `docs/specs/SPEC-RERERE.md`.

/// The exact content of `rr-cache/version`.
pub const VERSION: &[u8] = b"kit-rerere 1\n";

/// The largest side or postimage file an entry may hold.
pub const MAX_FILE: u64 = 256 << 20;

/// The domain tag of a conflict id.
const DOMAIN: &[u8] = b"kit-rerere-v1";

/// The two sides of a conflict in byte order: the lesser first. An absent
/// side is empty.
#[must_use]
pub fn sorted_sides<'a>(ours: &'a [u8], theirs: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    if ours <= theirs {
        (ours, theirs)
    } else {
        (theirs, ours)
    }
}

/// The id of the conflict between `ours` and `theirs`, as 64 lowercase hex
/// digits. Swapping the sides gives the same id.
#[must_use]
pub fn conflict_id(ours: &[u8], theirs: &[u8]) -> String {
    let (a, b) = sorted_sides(ours, theirs);
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&[0]);
    for side in [a, b] {
        hasher.update(&u64::try_from(side.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(side);
    }
    hasher.finalize().to_hex().to_string()
}

/// Whether `name` has the shape of a conflict id: 64 lowercase hex digits.
#[must_use]
pub fn is_id(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether an entry named `name` with the files `side1` and `side2` is
/// valid: the name is an id, `side1` is not greater than `side2`, both fit
/// the size cap, and the id of the two sides is the name.
#[must_use]
pub fn entry_is_valid(name: &str, side1: &[u8], side2: &[u8]) -> bool {
    let fits = |s: &[u8]| u64::try_from(s.len()).is_ok_and(|n| n <= MAX_FILE);
    is_id(name) && fits(side1) && fits(side2) && side1 <= side2 && conflict_id(side1, side2) == name
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_id_is_lowercase_hex_and_ignores_the_order_of_the_sides() {
        let id = conflict_id(b"main\n", b"topic\n");
        assert!(is_id(&id), "{id}");
        assert_eq!(id, conflict_id(b"topic\n", b"main\n"));
        assert_ne!(id, conflict_id(b"main\n", b"other\n"));
    }

    #[test]
    fn the_length_prefix_keeps_a_split_from_colliding() {
        assert_ne!(conflict_id(b"ab", b"c"), conflict_id(b"a", b"bc"));
        assert_ne!(conflict_id(b"", b"x"), conflict_id(b"x", b"x"));
    }

    #[test]
    fn an_entry_is_valid_only_with_its_own_sorted_sides() {
        let id = conflict_id(b"b", b"a");
        assert!(entry_is_valid(&id, b"a", b"b"));
        assert!(!entry_is_valid(&id, b"b", b"a"), "unsorted");
        assert!(!entry_is_valid(&id, b"a", b"c"), "changed side");
        assert!(!entry_is_valid(&id.to_uppercase(), b"a", b"b"));
        assert!(!entry_is_valid(&id[..63], b"a", b"b"));
    }

    proptest::proptest! {
        #[test]
        fn entry_invariants(
            ours in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
            theirs in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
            flip in proptest::num::usize::ANY,
        ) {
            let id = conflict_id(&ours, &theirs);
            proptest::prop_assert!(is_id(&id));
            proptest::prop_assert_eq!(&id, &conflict_id(&theirs, &ours));
            let (a, b) = sorted_sides(&ours, &theirs);
            proptest::prop_assert!(entry_is_valid(&id, a, b));
            // Changing one byte of a side makes the entry invalid.
            let mut changed = a.to_vec();
            if !changed.is_empty() {
                let i = flip % changed.len();
                changed[i] ^= 1;
                proptest::prop_assert!(!entry_is_valid(&id, &changed, b));
            }
        }
    }
}
