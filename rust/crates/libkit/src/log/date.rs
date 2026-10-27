//! Dates for the history filters.
//!
//! The grammar is small and explicit. It is not the free-form date grammar
//! of git. These forms are accepted, and they are tried in this order:
//!
//! - `@<unix-seconds>` is an exact Unix timestamp.
//! - `now` and `today` are the current instant.
//! - `yesterday` is 24 hours before the current instant.
//! - `<N> <unit> ago` is a span before the current instant. The unit is
//!   `second`, `minute`, `hour`, `day`, `week`, `month` or `year`, in the
//!   singular or the plural. A month is 30 days. A year is 365 days.
//! - `YYYY-MM-DD` is midnight UTC on that date.
//! - `YYYY-MM-DD HH:MM:SS` and `YYYY-MM-DDTHH:MM:SS[Z]` are an exact UTC
//!   instant.

const SECS_PER_MIN: u64 = 60;
const SECS_PER_HOUR: u64 = 60 * SECS_PER_MIN;
const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;
const SECS_PER_WEEK: u64 = 7 * SECS_PER_DAY;
const SECS_PER_MONTH: u64 = 30 * SECS_PER_DAY;
const SECS_PER_YEAR: u64 = 365 * SECS_PER_DAY;

/// Errors from reading a date.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text is empty, or only white space.
    #[error("empty date")]
    Empty,
    /// The text after `@` is not a Unix timestamp.
    #[error("invalid date '{0}': expected a Unix timestamp after '@'")]
    BadTimestamp(String),
    /// The text matches none of the accepted forms.
    #[error(
        "invalid date '{0}': expected @<unix-seconds>, now/today/yesterday, \
         '<N> <unit> ago', YYYY-MM-DD, or YYYY-MM-DD HH:MM:SS"
    )]
    Unrecognized(String),
}

/// Read `text` as a date and return it as Unix seconds.
///
/// `now` is the current instant in Unix seconds. The caller passes it, so
/// the relative forms give the same answer in a test every time. A span
/// that reaches before the epoch gives `0`.
///
/// # Errors
/// [`Error`] when the text is empty or matches no accepted form.
pub fn parse(text: &str, now: u64) -> Result<u64, Error> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::Empty);
    }
    if let Some(rest) = text.strip_prefix('@') {
        return rest
            .parse::<u64>()
            .map_err(|_| Error::BadTimestamp(text.to_owned()));
    }
    match text.to_ascii_lowercase().as_str() {
        "now" | "today" => return Ok(now),
        "yesterday" => return Ok(now.saturating_sub(SECS_PER_DAY)),
        _ => {}
    }
    if let Some(span) = parse_relative_ago(text) {
        return Ok(now.saturating_sub(span));
    }
    parse_absolute(text).ok_or_else(|| Error::Unrecognized(text.to_owned()))
}

/// `<N> <unit>(s) ago` as a number of seconds. `None` when the text has a
/// different shape.
fn parse_relative_ago(text: &str) -> Option<u64> {
    let rest = text.strip_suffix("ago")?.trim();
    let mut parts = rest.splitn(2, char::is_whitespace);
    let count: u64 = parts.next()?.trim().parse().ok()?;
    let unit = parts.next()?.trim().trim_end_matches('s');
    let per = match unit {
        "second" | "sec" => 1,
        "minute" | "min" => SECS_PER_MIN,
        "hour" => SECS_PER_HOUR,
        "day" => SECS_PER_DAY,
        "week" => SECS_PER_WEEK,
        "month" => SECS_PER_MONTH,
        "year" => SECS_PER_YEAR,
        _ => return None,
    };
    count.checked_mul(per)
}

/// `YYYY-MM-DD[ HH:MM:SS]` or `YYYY-MM-DDTHH:MM:SS[Z]` as Unix seconds in
/// UTC. `None` when the text has a different shape, a field is out of
/// range, or the instant does not fit in the result.
fn parse_absolute(text: &str) -> Option<u64> {
    let text = text.strip_suffix('Z').unwrap_or(text);
    let (date, time) = match text.split_once(['T', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (text, None),
    };
    let mut fields = date.splitn(4, '-');
    let year: i64 = fields.next()?.parse().ok()?;
    let month: u32 = fields.next()?.parse().ok()?;
    let day: u32 = fields.next()?.parse().ok()?;
    if fields.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (hour, minute, second) = match time {
        None => (0, 0, 0),
        Some(time) => {
            let mut fields = time.splitn(4, ':');
            let hour: u32 = fields.next()?.parse().ok()?;
            let minute: u32 = fields.next().unwrap_or("0").parse().ok()?;
            let second: u32 = fields.next().unwrap_or("0").parse().ok()?;
            if fields.next().is_some() || hour > 23 || minute > 59 || second > 60 {
                return None;
            }
            (hour, minute, second)
        }
    };
    let secs = days_from_civil(year, month, day)?
        .checked_mul(i64::try_from(SECS_PER_DAY).ok()?)?
        .checked_add(i64::from(hour) * i64::try_from(SECS_PER_HOUR).ok()?)?
        .checked_add(i64::from(minute) * i64::try_from(SECS_PER_MIN).ok()?)?
        .checked_add(i64::from(second))?;
    u64::try_from(secs).ok()
}

/// A civil date as days since the epoch. This is the `days_from_civil`
/// algorithm of Howard Hinnant, exact over the proleptic Gregorian
/// calendar. `None` when the day count does not fit in an `i64`.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = if year >= 0 {
        year
    } else {
        year.checked_sub(399)?
    } / 400;
    let year_of_era = year - era * 400; // [0, 399]
    let month_index = i64::from(if month > 2 { month - 3 } else { month + 9 }); // [0, 11]
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1; // [0, 365]
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year; // [0, 146096]
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000; // 2023-11-14 22:13:20 UTC

    #[test]
    fn epoch_spelling() {
        assert_eq!(parse("@1700000000", NOW), Ok(1_700_000_000));
    }

    #[test]
    fn now_today_yesterday() {
        assert_eq!(parse("now", NOW), Ok(NOW));
        assert_eq!(parse("Today", NOW), Ok(NOW));
        assert_eq!(parse("yesterday", NOW), Ok(NOW - 86_400));
    }

    #[test]
    fn relative_ago_units() {
        assert_eq!(parse("30 seconds ago", NOW), Ok(NOW - 30));
        assert_eq!(parse("5 minutes ago", NOW), Ok(NOW - 300));
        assert_eq!(parse("2 hours ago", NOW), Ok(NOW - 7_200));
        assert_eq!(parse("1 day ago", NOW), Ok(NOW - 86_400));
        assert_eq!(parse("2 weeks ago", NOW), Ok(NOW - 2 * 604_800));
        assert_eq!(parse("1 month ago", NOW), Ok(NOW - 2_592_000));
        assert_eq!(parse("1 year ago", NOW), Ok(NOW - 31_536_000));
    }

    #[test]
    fn a_span_before_the_epoch_gives_zero() {
        assert_eq!(parse("99999 years ago", NOW), Ok(0));
    }

    #[test]
    fn absolute_date_only_is_midnight_utc() {
        assert_eq!(parse("1970-01-01", NOW), Ok(0));
        // 2023-11-14 00:00:00 UTC.
        assert_eq!(parse("2023-11-14", NOW), Ok(1_699_920_000));
    }

    #[test]
    fn absolute_date_time_space_and_t_separator() {
        assert_eq!(parse("2023-11-14 22:13:20", NOW), Ok(1_700_000_000));
        assert_eq!(parse("2023-11-14T22:13:20", NOW), Ok(1_700_000_000));
        assert_eq!(parse("2023-11-14T22:13:20Z", NOW), Ok(1_700_000_000));
    }

    #[test]
    fn leap_day_round_trips() {
        // 2020-02-29 00:00:00 UTC.
        assert_eq!(parse("2020-02-29", NOW), Ok(1_582_934_400));
    }

    #[test]
    fn each_failure_has_its_own_error() {
        assert_eq!(parse("", NOW), Err(Error::Empty));
        assert_eq!(parse("   ", NOW), Err(Error::Empty));
        assert_eq!(
            parse("@nope", NOW),
            Err(Error::BadTimestamp("@nope".into()))
        );
        for text in [
            "not-a-date",
            "2023-13-01",
            "2023-11-32",
            "2023-11-14 24:00:00",
        ] {
            assert_eq!(parse(text, NOW), Err(Error::Unrecognized(text.into())));
        }
    }

    #[test]
    fn the_messages_keep_their_wording() {
        assert_eq!(Error::Empty.to_string(), "empty date");
        assert_eq!(
            Error::BadTimestamp("@x".into()).to_string(),
            "invalid date '@x': expected a Unix timestamp after '@'"
        );
        assert_eq!(
            Error::Unrecognized("x".into()).to_string(),
            "invalid date 'x': expected @<unix-seconds>, now/today/yesterday, \
             '<N> <unit> ago', YYYY-MM-DD, or YYYY-MM-DD HH:MM:SS"
        );
    }

    #[test]
    fn a_year_that_overflows_is_rejected_and_does_not_panic() {
        assert_eq!(
            parse("9223372036854775807-12-31", NOW),
            Err(Error::Unrecognized("9223372036854775807-12-31".into()))
        );
        // The largest year whose seconds fit in an `i64` still parses.
        assert!(parse("99999999999-01-01", NOW).is_ok());
    }
}
