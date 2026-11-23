//! Continuing an interrupted download with an HTTP `Range` request.
//!
//! A transport that read part of a pack may ask for the rest. It resumes
//! opaque bytes only: whatever the remote answers, the pack is checked as a
//! whole against its key before it is used, so a prefix that was damaged or
//! came from another object fails there. The checks here keep a transport
//! from appending bytes that are not the rest of the same body, which would
//! only cost a failed attempt.

/// Why a transport read a body from its start instead of continuing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RestartReason {
    /// The answer was not a partial response, or was a refusal to range.
    Status,
    /// The answer's entity tag was missing, weak, or not the first one.
    Validator,
    /// The answer's range or length was not exactly the rest of the body.
    Range,
}

impl RestartReason {
    /// A short name for traces.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Validator => "validator",
            Self::Range => "range",
        }
    }
}

/// How a transport answered a request to continue a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResumeOutcome {
    /// The body continued, and `bytes` bytes were not fetched again.
    Resumed { bytes: u64 },
    /// The body was read again from its start.
    Restarted { reason: RestartReason },
}

/// What the first answer of a body promises about it: a strong entity tag and
/// the full length. A later answer continues the body only if it carries the
/// same tag and exactly the rest of that length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validator {
    etag: String,
    total: u64,
}

impl Validator {
    /// The validator of a full answer, or `None` when it cannot anchor a
    /// resume: no entity tag, a weak one, or no length.
    #[must_use]
    pub fn new(etag: Option<&str>, total: Option<u64>) -> Option<Self> {
        let etag = etag?.trim();
        let total = total.filter(|&total| total > 0)?;
        let strong = etag.len() >= 2
            && etag.starts_with('"')
            && etag.ends_with('"')
            && !etag.bytes().any(|byte| byte.is_ascii_control());
        strong.then(|| Self {
            etag: etag.to_owned(),
            total,
        })
    }

    /// The full length of the body.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The entity tag to send as `If-Match`.
    #[must_use]
    pub fn etag(&self) -> &str {
        &self.etag
    }

    /// The `Range` header value that asks for the body from `offset` to its
    /// end.
    #[must_use]
    pub fn range(offset: u64) -> String {
        format!("bytes={offset}-")
    }

    /// Whether an answer to [`Self::range`]`(offset)` is exactly the rest of
    /// the body: status 206, the same entity tag, `Content-Range` from
    /// `offset` to the last byte of the same total, and a `Content-Length`
    /// of the bytes left.
    ///
    /// # Errors
    /// The reason it is not.
    pub fn accepts(
        &self,
        offset: u64,
        status: u16,
        etag: Option<&str>,
        content_range: Option<&str>,
        content_length: Option<u64>,
    ) -> Result<(), RestartReason> {
        if status != 206 {
            return Err(RestartReason::Status);
        }
        if etag.map(str::trim) != Some(self.etag.as_str()) {
            return Err(RestartReason::Validator);
        }
        let left = self.total.checked_sub(offset).filter(|&left| left > 0);
        let exact = left.is_some_and(|left| {
            content_length == Some(left)
                && content_range.and_then(parse_content_range)
                    == Some((offset, self.total - 1, self.total))
        });
        if exact {
            Ok(())
        } else {
            Err(RestartReason::Range)
        }
    }
}

/// The `(first, last, total)` of `bytes first-last/total`, or `None` for any
/// other form, including an unknown total.
fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let rest = value.trim().strip_prefix("bytes ")?;
    let (span, total) = rest.split_once('/')?;
    let (first, last) = span.split_once('-')?;
    let number = |text: &str| {
        (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse::<u64>().ok())
            .flatten()
    };
    Some((number(first)?, number(last)?, number(total)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator() -> Validator {
        Validator::new(Some("\"abc\""), Some(100)).unwrap()
    }

    #[test]
    fn only_a_strong_tag_with_a_length_anchors_a_resume() {
        assert!(Validator::new(Some("\"abc\""), Some(1)).is_some());
        assert!(Validator::new(Some("W/\"abc\""), Some(1)).is_none());
        assert!(Validator::new(Some("abc"), Some(1)).is_none());
        assert!(Validator::new(Some("\""), Some(1)).is_none());
        assert!(Validator::new(None, Some(1)).is_none());
        assert!(Validator::new(Some("\"abc\""), None).is_none());
        assert!(Validator::new(Some("\"abc\""), Some(0)).is_none());
        assert!(Validator::new(Some("\"a\nb\""), Some(1)).is_none());
    }

    #[test]
    fn a_validator_gives_back_its_tag_and_length() {
        let held = validator();
        assert_eq!(held.etag(), "\"abc\"");
        assert_eq!(held.total(), 100);
        let other = Validator::new(Some(" \"x-7\" "), Some(4096)).unwrap();
        assert_eq!(other.etag(), "\"x-7\"");
        assert_eq!(other.total(), 4096);
    }

    #[test]
    fn range_asks_for_the_rest() {
        assert_eq!(Validator::range(40), "bytes=40-");
    }

    #[test]
    fn an_exact_partial_answer_is_accepted() {
        let v = validator();
        assert_eq!(
            v.accepts(40, 206, Some("\"abc\""), Some("bytes 40-99/100"), Some(60)),
            Ok(())
        );
    }

    #[test]
    fn every_other_answer_is_refused_with_its_reason() {
        let v = validator();
        let ok = (Some("\"abc\""), Some("bytes 40-99/100"), Some(60));
        let check = |status, etag, range, length| v.accepts(40, status, etag, range, length);
        assert_eq!(check(200, ok.0, ok.1, ok.2), Err(RestartReason::Status));
        assert_eq!(check(412, ok.0, ok.1, ok.2), Err(RestartReason::Status));
        assert_eq!(check(206, None, ok.1, ok.2), Err(RestartReason::Validator));
        assert_eq!(
            check(206, Some("\"other\""), ok.1, ok.2),
            Err(RestartReason::Validator)
        );
        assert_eq!(
            check(206, Some("W/\"abc\""), ok.1, ok.2),
            Err(RestartReason::Validator)
        );
        for range in [
            None,
            Some("bytes 41-99/100"),
            Some("bytes 40-98/100"),
            Some("bytes 40-99/101"),
            Some("bytes 40-99/*"),
            Some("bytes */100"),
            Some("items 40-99/100"),
            Some("bytes 40-99/1e2"),
            Some("bytes +40-99/100"),
        ] {
            assert_eq!(check(206, ok.0, range, ok.2), Err(RestartReason::Range));
        }
        for length in [None, Some(59), Some(61), Some(100)] {
            assert_eq!(check(206, ok.0, ok.1, length), Err(RestartReason::Range));
        }
    }

    #[test]
    fn an_offset_at_or_past_the_end_is_never_a_continuation() {
        let v = validator();
        assert_eq!(
            v.accepts(100, 206, Some("\"abc\""), Some("bytes 100-99/100"), Some(0)),
            Err(RestartReason::Range)
        );
        assert_eq!(
            v.accepts(101, 206, Some("\"abc\""), Some("bytes 101-99/100"), Some(0)),
            Err(RestartReason::Range)
        );
    }
}
