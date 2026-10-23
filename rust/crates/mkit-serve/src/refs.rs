//! Ref names, listing prefixes and the `UpdateRef` wire fields
//! (SPEC-REFS §§2-4, SPEC-TRANSPORT §4.2.1).

use mkit_core::hash::Hash;
use mkit_core::refs::RefWriteCondition;

/// The longest ref name in bytes (SPEC-REFS §3).
pub const MAX_REF_NAME_BYTES: usize = mkit_core::refs::MAX_REF_NAME_BYTES;

/// The reply for a ref name or listing prefix over [`MAX_REF_NAME_BYTES`].
pub const REF_NAME_TOO_LONG: &str = "ref name too long";

/// The directory that holds every served ref, as a name prefix.
pub(crate) const SERVED_REFS_PREFIX: &str = "refs/";

/// The reply for a valid ref name outside `refs/` (SPEC-REFS §2).
pub const REF_NAME_OUTSIDE_REFS: &str =
    "ref name must start with refs/ (the server serves only refs under refs/)";

/// Whether the server serves `name`: a valid ref name under `refs/`.
#[must_use]
pub fn is_served_ref_name(name: &str) -> bool {
    name.starts_with(SERVED_REFS_PREFIX) && mkit_core::refs::validate_ref_name(name)
}

/// The scan prefix of a listing prefix (SPEC-REFS §4). It is empty for an
/// empty prefix. Otherwise it is the prefix with its trailing `/` characters
/// replaced by exactly one. A listing covers the refs whose name starts with
/// it, so a prefix matches only at a path-component boundary.
#[must_use]
pub(crate) fn list_scan_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

/// The wire field a digest came from. The reply names the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestField {
    /// `pack_id` of `PackExists` or `DownloadPack`.
    Pack,
    /// `new_id` of `UpdateRef`.
    New,
    /// `expected_id` of a `MATCH` write.
    Expected,
}

/// A 32-byte digest from a wire `bytes` field.
///
/// # Errors
/// The reply text when `bytes` is absent or not 32 bytes long.
pub(crate) fn digest(field: DigestField, bytes: Option<&[u8]>) -> Result<Hash, &'static str> {
    let bad = |absent: bool| match (field, absent) {
        (DigestField::Pack, true) => "pack_id missing",
        (DigestField::Pack, false) => "pack_id must be 32 bytes",
        (DigestField::New, _) => "new_id must be 32 bytes",
        (DigestField::Expected, _) => "MATCH expectation requires a 32-byte expected_id",
    };
    let bytes = bytes.ok_or_else(|| bad(true))?;
    Hash::try_from(bytes).map_err(|_| bad(false))
}

/// The wire numbers of `RefExpectation`.
const EXPECT_ANY: i32 = 1;
const EXPECT_MISSING: i32 = 2;
const EXPECT_MATCH: i32 = 3;

/// A write condition from the wire pair `(expectation, expected_id)`. The
/// ssh wire ignores `expected_id` for `ANY` and `MISSING`.
///
/// # Errors
/// The reply text for an unspecified expectation, or for a `MATCH` without
/// a 32-byte `expected_id`.
pub(crate) fn condition(
    expectation: i32,
    expected_id: &[u8],
) -> Result<RefWriteCondition, &'static str> {
    match expectation {
        EXPECT_ANY => Ok(RefWriteCondition::Any),
        EXPECT_MISSING => Ok(RefWriteCondition::Missing),
        EXPECT_MATCH => {
            digest(DigestField::Expected, Some(expected_id)).map(RefWriteCondition::Match)
        }
        _ => Err("UpdateRef.expectation is required"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_names_live_under_refs() {
        assert!(is_served_ref_name("refs/heads/main"));
        assert!(!is_served_ref_name("main"));
        assert!(!is_served_ref_name("heads/main"));
        assert!(!is_served_ref_name("refs/heads/.hidden"));
        assert!(!is_served_ref_name("refs/"));
    }

    #[test]
    fn scan_prefix_ends_at_one_slash() {
        assert_eq!(list_scan_prefix(""), "");
        assert_eq!(list_scan_prefix("/"), "");
        assert_eq!(list_scan_prefix("refs//"), "refs/");
        assert_eq!(list_scan_prefix("refs/heads"), "refs/heads/");
        assert_eq!(list_scan_prefix("refs/heads/main"), "refs/heads/main/");
    }

    #[test]
    fn digest_names_its_field() {
        assert_eq!(digest(DigestField::Pack, None), Err("pack_id missing"));
        assert_eq!(
            digest(DigestField::Pack, Some(&[0; 3])),
            Err("pack_id must be 32 bytes")
        );
        assert_eq!(
            digest(DigestField::New, Some(&[])),
            Err("new_id must be 32 bytes")
        );
        assert_eq!(
            digest(DigestField::Expected, None),
            Err("MATCH expectation requires a 32-byte expected_id")
        );
        assert_eq!(digest(DigestField::Pack, Some(&[7; 32])), Ok([7; 32]));
    }

    #[test]
    fn condition_follows_the_wire_numbers() {
        assert_eq!(condition(1, &[9; 3]), Ok(RefWriteCondition::Any));
        assert_eq!(condition(2, &[9; 32]), Ok(RefWriteCondition::Missing));
        assert_eq!(
            condition(3, &[4; 32]),
            Ok(RefWriteCondition::Match([4; 32]))
        );
        assert!(condition(3, &[4; 31]).is_err());
        assert_eq!(condition(0, &[]), Err("UpdateRef.expectation is required"));
        assert_eq!(condition(9, &[]), Err("UpdateRef.expectation is required"));
    }
}
