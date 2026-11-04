//! Replay classification of a signed write (SPEC-TRANSPORT-CONNECT §7.1).
//!
//! Authenticate the envelope, including its validity window, before the replay
//! lookup. The lookup is the second step of the order in §7.1. This module is
//! pure: the host reads the replay record, passes it in, and commits the
//! outcome with the effects of the write. A record's pruning time never
//! extends the validity of an envelope, so no clock enters here.

use crate::hash::Hash;

/// The replay record that the host found for (audience, repository, signer,
/// nonce), after authentication. `R` is the host's stored result. The host
/// never supplies a challenge, a transient refusal or a pending answer as a
/// stored result.
#[derive(Debug)]
pub struct ReplayObservation<'a, R> {
    /// Fingerprint of the authenticated operation that created the record,
    /// from the verified envelope.
    pub fingerprint: Hash,
    /// The stored state.
    pub state: ReplayStateView<'a, R>,
}

/// The stored state of a replay record.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReplayStateView<'a, R> {
    /// The write started and did not finish.
    InFlight {
        /// Whether the host can resume the same reservation. Only an
        /// un-ticketed `UploadPack` on a single-repository deployment can.
        resumable: bool,
    },
    /// The write finished, and its result is stored.
    Committed(RecordedResult<'a, R>),
}

/// A stored terminal result: a success, or a permanent refusal.
///
/// A permanent refusal can be built only through [`storable_rejection`], so a
/// challenge, a transient refusal and an unknown code have no representation.
#[derive(Debug)]
#[must_use]
pub struct RecordedResult<'a, R> {
    result: &'a R,
    rejection: Option<PermanentCode>,
}

impl<'a, R> RecordedResult<'a, R> {
    /// A success that the host has seen committed. Do not pass an error or a
    /// pending answer here.
    pub const fn success(result: &'a R) -> Self {
        Self {
            result,
            rejection: None,
        }
    }

    /// A refusal, if it may be stored as a terminal result. `code` is the
    /// Connect code, and `admission_challenge` is true for an admission
    /// challenge (§5.1). Returns `None` when the refusal must not be stored.
    #[must_use]
    pub const fn rejection(result: &'a R, code: &str, admission_challenge: bool) -> Option<Self> {
        match storable_rejection(code, admission_challenge) {
            Some(code) => Some(Self {
                result,
                rejection: Some(code),
            }),
            None => None,
        }
    }

    /// The code of the refusal, or `None` for a success.
    #[must_use]
    pub const fn rejection_code(&self) -> Option<PermanentCode> {
        self.rejection
    }
}

/// The outcome of the replay lookup.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum ReplayDecision<'a, R> {
    /// No record exists. The write is new and continues to authorization.
    Fresh,
    /// The same operation finished. Return this stored result and repeat no
    /// effect.
    Recorded(&'a R),
    /// The same operation is in flight and the host can resume it.
    Resume,
    /// The same operation is in flight. Answer with a retryable `aborted`.
    InFlight,
    /// The record belongs to a different operation. Answer `invalid_argument`.
    Conflict,
}

/// Classify the replay record against the fingerprint of the request.
///
/// A fingerprint mismatch wins over every stored state, so one signer's result
/// never reaches a different operation.
///
/// # Examples
/// ```
/// use kit_core::write_auth::replay::{ReplayDecision, classify_replay};
/// assert_eq!(classify_replay::<()>(None, &[0; 32]), ReplayDecision::Fresh);
/// ```
pub fn classify_replay<'a, R>(
    existing: Option<ReplayObservation<'a, R>>,
    fingerprint: &Hash,
) -> ReplayDecision<'a, R> {
    match existing {
        None => ReplayDecision::Fresh,
        Some(record) if record.fingerprint != *fingerprint => ReplayDecision::Conflict,
        Some(record) => match record.state {
            ReplayStateView::Committed(stored) => ReplayDecision::Recorded(stored.result),
            ReplayStateView::InFlight { resumable: true } => ReplayDecision::Resume,
            ReplayStateView::InFlight { resumable: false } => ReplayDecision::InFlight,
        },
    }
}

/// A Connect code that may be stored as a terminal refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PermanentCode {
    /// `invalid_argument`
    InvalidArgument,
    /// `not_found`
    NotFound,
    /// `already_exists`
    AlreadyExists,
    /// `permission_denied`
    PermissionDenied,
    /// `failed_precondition`
    FailedPrecondition,
    /// `out_of_range`
    OutOfRange,
    /// `unimplemented`
    Unimplemented,
}

impl PermanentCode {
    /// Parse a Connect code. Every code outside the seven permanent ones is
    /// refused, including `unavailable`, `aborted` and an unknown future code.
    #[must_use]
    pub const fn from_code(code: &str) -> Option<Self> {
        Some(match code.as_bytes() {
            b"invalid_argument" => Self::InvalidArgument,
            b"not_found" => Self::NotFound,
            b"already_exists" => Self::AlreadyExists,
            b"permission_denied" => Self::PermissionDenied,
            b"failed_precondition" => Self::FailedPrecondition,
            b"out_of_range" => Self::OutOfRange,
            b"unimplemented" => Self::Unimplemented,
            _ => return None,
        })
    }

    /// The Connect code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::PermissionDenied => "permission_denied",
            Self::FailedPrecondition => "failed_precondition",
            Self::OutOfRange => "out_of_range",
            Self::Unimplemented => "unimplemented",
        }
    }
}

/// The code of a refusal that may be stored as a terminal result, or `None`.
///
/// Only the seven permanent codes qualify, and an admission challenge never
/// does, whatever its code. The host stores no rejection details.
#[must_use]
pub const fn storable_rejection(code: &str, admission_challenge: bool) -> Option<PermanentCode> {
    if admission_challenge {
        None
    } else {
        PermanentCode::from_code(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAME: Hash = [7; 32];
    const OTHER: Hash = [8; 32];

    #[derive(Debug, PartialEq)]
    struct Saved(&'static str);

    fn stored<'a>(name: &str, saved: &'a Saved) -> Option<ReplayStateView<'a, Saved>> {
        Some(match name {
            "absent" => return None,
            "committed" => ReplayStateView::Committed(RecordedResult::success(saved)),
            "rejected" => ReplayStateView::Committed(
                RecordedResult::rejection(saved, "not_found", false).unwrap(),
            ),
            "resumable" => ReplayStateView::InFlight { resumable: true },
            "in flight" => ReplayStateView::InFlight { resumable: false },
            _ => panic!("unknown state {name}"),
        })
    }

    /// Every stored state, with the decision for the same and for a different
    /// fingerprint.
    #[test]
    fn classifier_table() {
        let saved = Saved("saved result");
        let table = [
            ("absent", ReplayDecision::Fresh, ReplayDecision::Fresh),
            (
                "committed",
                ReplayDecision::Recorded(&saved),
                ReplayDecision::Conflict,
            ),
            (
                "rejected",
                ReplayDecision::Recorded(&saved),
                ReplayDecision::Conflict,
            ),
            (
                "resumable",
                ReplayDecision::Resume,
                ReplayDecision::Conflict,
            ),
            (
                "in flight",
                ReplayDecision::InFlight,
                ReplayDecision::Conflict,
            ),
        ];
        for (name, same, different) in table {
            for (fingerprint, want) in [(SAME, same), (OTHER, different)] {
                let observation = stored(name, &saved).map(|state| ReplayObservation {
                    fingerprint: SAME,
                    state,
                });
                let got = classify_replay(observation, &fingerprint);
                assert_eq!(got, want, "{name}");
                if let ReplayDecision::Recorded(result) = got {
                    // The host's own value comes back, not a copy.
                    assert!(std::ptr::eq(result, &raw const saved));
                }
            }
        }
    }

    /// Every Connect code, with whether a refusal may store it.
    const CODES: [(&str, bool); 17] = [
        ("canceled", false),
        ("unknown", false),
        ("invalid_argument", true),
        ("deadline_exceeded", false),
        ("not_found", true),
        ("already_exists", true),
        ("permission_denied", true),
        ("resource_exhausted", false),
        ("failed_precondition", true),
        ("aborted", false),
        ("out_of_range", true),
        ("unimplemented", true),
        ("internal", false),
        ("unavailable", false),
        ("data_loss", false),
        ("unauthenticated", false),
        ("future_code", false),
    ];

    #[test]
    fn only_the_seven_permanent_codes_are_storable() {
        let saved = Saved("refusal");
        for (code, storable) in CODES {
            let permanent = storable_rejection(code, false);
            assert_eq!(permanent.is_some(), storable, "{code}");
            assert_eq!(permanent, PermanentCode::from_code(code), "{code}");
            if let Some(permanent) = permanent {
                assert_eq!(permanent.as_str(), code);
            }
            let recorded = RecordedResult::rejection(&saved, code, false);
            assert_eq!(recorded.is_some(), storable, "{code}");
            assert_eq!(
                recorded.and_then(|recorded| recorded.rejection_code()),
                permanent,
                "{code}"
            );
            // An admission challenge is never stored, whatever its code.
            assert_eq!(storable_rejection(code, true), None, "challenge {code}");
            assert!(RecordedResult::rejection(&saved, code, true).is_none());
        }
        assert_eq!(RecordedResult::success(&saved).rejection_code(), None);
    }

    #[test]
    fn code_spelling_is_exact() {
        for code in [
            "",
            "Not_Found",
            "not_found ",
            " not_found",
            "not-found",
            "NOT_FOUND",
        ] {
            assert_eq!(PermanentCode::from_code(code), None, "{code:?}");
        }
    }
}
