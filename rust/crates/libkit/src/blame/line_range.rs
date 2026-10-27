//! Line ranges for blame.
//!
//! A range is the text after `-L` in `git blame`. These forms are accepted:
//!
//! - `<start>,<end>` is the lines from `start` to `end`, both included.
//! - `<start>,+<n>` is `n` lines from `start`.
//! - `<start>,-<n>` is `n` lines that end at `start`.
//! - `<start>,` and a bare `<start>` run from `start` to the end of the file.
//! - `,<end>` runs from the first line to `end`.
//!
//! Line numbers start at 1. A range with `end` before `start` is swapped. An
//! `end` past the end of the file is cut to the last line. A `start` past the
//! end of the file is an error.

/// Errors from reading a line range.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A token is not an integer.
    #[error("invalid line number '{0}' in -L range")]
    NotANumber(String),
    /// A line number is an integer below 1.
    #[error("-L invalid line number: {0}")]
    InvalidLineNumber(String),
    /// An offset is `+0` or `-0`.
    #[error("-L invalid empty range")]
    EmptyRange,
    /// The first line of the range is past the end of the file.
    #[error("file {file} has only {total} lines")]
    PastEnd {
        /// The file that the range applies to.
        file: String,
        /// The number of lines of the file.
        total: usize,
    },
}

/// Read `spec` as a range of lines in a file of `total` lines.
///
/// The result is the first and the last line of the range, both included and
/// 1-based. The first line is at least 1 and at most `total`. The last line
/// is at least the first line and at most `total`. `file` is only for the
/// text of an error.
///
/// # Errors
/// [`Error`] when a token is not a line number, when an offset is zero, or
/// when the range starts past the end of the file.
pub fn parse(spec: &str, total: usize, file: &str) -> Result<(usize, usize), Error> {
    let (start_token, end_token) = match spec.split_once(',') {
        Some((start, end)) => (start.trim(), Some(end.trim())),
        None => (spec.trim(), None),
    };

    // An empty start is line 1.
    let start = if start_token.is_empty() {
        1
    } else {
        parse_line_number(start_token)?
    };

    // The end token gives the bounds:
    //   none or empty  runs to the end of the file
    //   `<m>`          swaps with the start when it is before it
    //   `+<n>`         is `n` lines from the start
    //   `-<n>`         is `n` lines that end at the start, and the first line
    //                  is cut up to line 1
    let (first, last) = match end_token {
        None | Some("") => (start, total),
        Some(token) if token.starts_with('+') => {
            (start, start.saturating_add(parse_offset(token)? - 1))
        }
        Some(token) if token.starts_with('-') => {
            let count = parse_offset(token)?;
            (start.saturating_sub(count - 1).max(1), start)
        }
        Some(token) => {
            let end = parse_line_number(token)?;
            if start > end {
                (end, start)
            } else {
                (start, end)
            }
        }
    };

    // The check for an empty file comes after the token checks. A token that
    // is a zero or an empty range then reports its own error first, as git
    // does.
    if total == 0 {
        return Err(Error::PastEnd {
            file: file.to_owned(),
            total: 0,
        });
    }

    // The first line has to be in the file. An `end` past the file is cut.
    if first > total {
        return Err(Error::PastEnd {
            file: file.to_owned(),
            total,
        });
    }
    Ok((first, last.min(total)))
}

/// Read a 1-based line number. An integer below 1 gets its own error. Text
/// that is not an integer gets another.
fn parse_line_number(token: &str) -> Result<usize, Error> {
    match token.parse::<usize>() {
        Ok(number) if number >= 1 => Ok(number),
        // `0`, or a negative integer, which `usize` refuses.
        _ if token.parse::<i64>().is_ok() => Err(Error::InvalidLineNumber(token.to_owned())),
        _ => Err(Error::NotANumber(token.to_owned())),
    }
}

/// Read the count of a `+<n>` or `-<n>` token. The token includes the sign.
fn parse_offset(token: &str) -> Result<usize, Error> {
    let digits = &token[1..];
    let count = digits
        .parse::<usize>()
        .map_err(|_| Error::NotANumber(digits.to_owned()))?;
    if count == 0 {
        return Err(Error::EmptyRange);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The rules are the ones of `git blame -L`: both ends are included, `+n`
    // is `n` lines, a bare start runs to the end of the file, an inverted
    // range swaps, and an end past the file is cut.

    /// The file name only appears in the text of an error.
    fn range(spec: &str, total: usize) -> Result<(usize, usize), Error> {
        parse(spec, total, "f.txt")
    }

    fn message(spec: &str, total: usize) -> String {
        range(spec, total).unwrap_err().to_string()
    }

    #[test]
    fn an_explicit_range_includes_both_ends() {
        assert_eq!(range("3,5", 8), Ok((3, 5)));
    }

    #[test]
    fn plus_n_is_n_lines_from_the_start() {
        assert_eq!(range("3,+2", 8), Ok((3, 4)));
        assert_eq!(range("1,+1", 8), Ok((1, 1)));
    }

    #[test]
    fn minus_n_is_n_lines_that_end_at_the_start() {
        assert_eq!(range("5,-2", 8), Ok((4, 5)));
        assert_eq!(range("8,-3", 8), Ok((6, 8)));
        assert_eq!(range("3,-1", 8), Ok((3, 3)));
        assert_eq!(range("2,-5", 8), Ok((1, 2)));
    }

    #[test]
    fn minus_n_with_a_start_past_the_end_checks_the_first_line() {
        // `12,-3` on 8 lines is 10 to 12, and 10 is past the end.
        assert!(message("12,-3", 8).contains("only 8 lines"));
        assert_eq!(range("8,-3", 8), Ok((6, 8)));
    }

    #[test]
    fn an_open_end_runs_to_the_end_of_the_file() {
        assert_eq!(range("4,", 8), Ok((4, 8)));
        assert_eq!(range("3", 8), Ok((3, 8)));
    }

    #[test]
    fn an_open_start_is_line_one() {
        assert_eq!(range(",3", 8), Ok((1, 3)));
    }

    #[test]
    fn an_inverted_range_swaps() {
        assert_eq!(range("5,2", 8), Ok((2, 5)));
    }

    #[test]
    fn an_end_past_the_file_is_cut() {
        assert_eq!(range("3,99", 8), Ok((3, 8)));
    }

    #[test]
    fn a_start_past_the_file_is_an_error() {
        assert_eq!(
            range("99,100", 8),
            Err(Error::PastEnd {
                file: "f.txt".into(),
                total: 8
            })
        );
        assert_eq!(message("99,100", 8), "file f.txt has only 8 lines");
    }

    #[test]
    fn an_empty_file_has_zero_lines_for_every_form_without_a_zero_token() {
        for spec in ["1,", "3", "1,3", "2,5"] {
            assert_eq!(
                parse(spec, 0, "empty.txt").unwrap_err().to_string(),
                "file empty.txt has only 0 lines",
                "spec {spec:?}"
            );
        }
        for spec in [",0", "3,0"] {
            assert_eq!(
                parse(spec, 0, "empty.txt").unwrap_err().to_string(),
                "-L invalid line number: 0",
                "spec {spec:?}"
            );
        }
    }

    #[test]
    fn a_zero_line_number_is_invalid_in_every_form() {
        for spec in [",0", "3,0", "0,0", "0", "0,", "0,5"] {
            assert_eq!(
                message(spec, 8),
                "-L invalid line number: 0",
                "spec {spec:?}"
            );
        }
    }

    #[test]
    fn a_negative_line_number_names_its_token() {
        assert_eq!(message("-3,5", 8), "-L invalid line number: -3");
    }

    #[test]
    fn a_zero_offset_is_an_empty_range() {
        assert_eq!(range("3,+0", 8), Err(Error::EmptyRange));
        assert_eq!(range("3,-0", 8), Err(Error::EmptyRange));
        assert_eq!(message("3,+0", 8), "-L invalid empty range");
    }

    #[test]
    fn text_that_is_not_a_number_is_an_error() {
        assert_eq!(message("a,b", 8), "invalid line number 'a' in -L range");
        assert_eq!(message("3,+x", 8), "invalid line number 'x' in -L range");
        assert_eq!(message("3,x", 8), "invalid line number 'x' in -L range");
    }

    #[test]
    fn a_huge_number_does_not_overflow() {
        assert_eq!(range("3,+18446744073709551615", 8), Ok((3, 8)));
        assert_eq!(
            range("18446744073709551615,-18446744073709551615", 8),
            Ok((1, 8))
        );
        assert!(range("99999999999999999999999,1", 8).is_err());
    }

    #[test]
    fn white_space_around_a_token_is_ignored() {
        assert_eq!(range(" 3 , 5 ", 8), Ok((3, 5)));
    }
}
