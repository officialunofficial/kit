//! Patch mails (SPEC-PATCH §5): split a mailbox and read the author, the
//! message and the patch of each mail.

use std::fmt;

use super::patch;

/// One mail, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    /// The author, from `From:`, with encoded words decoded.
    pub author: String,
    /// The commit message: the cleaned subject, then the body up to `---`
    /// or the first file patch.
    pub message: String,
    /// The text from the end of the message on, which holds the patch.
    pub patch: Vec<u8>,
}

/// Why a mail was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailError {
    /// No `From:` header.
    NoAuthor,
    /// A `Content-Transfer-Encoding` other than `7bit` or `8bit`.
    Encoding(String),
    /// The patch text does not parse, or holds no file patch.
    Patch(patch::ParseError),
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAuthor => write!(f, "the mail has no From: header"),
            Self::Encoding(e) => write!(f, "content transfer encoding '{e}' is not supported"),
            Self::Patch(e) if e.kind == patch::ParseErrorKind::NoPatch => {
                write!(f, "the mail holds no patch")
            }
            Self::Patch(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MailError {}

/// Split a mailbox at each `From ` line that `git mailsplit` splits on. Text
/// before the first such line is a mail of its own when it holds anything
/// but whitespace, so a file with no such line is one mail.
#[must_use]
pub fn split(text: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut at = 0;
    for line in text.split_inclusive(|&b| b == b'\n') {
        if is_from_line(line) && at > start {
            out.push(&text[start..at]);
            start = at;
        }
        at += line.len();
    }
    out.push(&text[start..]);
    out.retain(|m| !m.iter().all(u8::is_ascii_whitespace));
    out
}

/// A `From ` line with a ctime date, as `git mailsplit` tests it: a time
/// `hh:mm:ss` followed by a year after 1990.
#[must_use]
pub fn is_from_line(line: &[u8]) -> bool {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    if line.len() < 19 || !line.starts_with(b"From ") {
        return false;
    }
    let Some(colon) = line.iter().rposition(|&b| b == b':') else {
        return false;
    };
    let digit = |i: Option<usize>| i.and_then(|i| line.get(i)).is_some_and(u8::is_ascii_digit);
    if colon < 9
        || !digit(colon.checked_sub(4))
        || !digit(colon.checked_sub(2))
        || !digit(colon.checked_sub(1))
        || !digit(Some(colon + 1))
        || !digit(Some(colon + 2))
    {
        return false;
    }
    let year: Vec<u8> = line[colon + 3..]
        .iter()
        .skip_while(|b| **b == b' ')
        .take_while(|b| b.is_ascii_digit())
        .take(9)
        .copied()
        .collect();
    std::str::from_utf8(&year)
        .ok()
        .and_then(|y| y.parse::<u32>().ok())
        .is_some_and(|y| y > 90)
}

/// Read one mail of [`split`].
///
/// # Errors
/// [`MailError`] for a mail with no author, an unsupported encoding or a
/// patch that does not parse.
pub fn parse(mail: &[u8]) -> Result<Mail, MailError> {
    let mut lines: Vec<&[u8]> = mail
        .split_inclusive(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\n").unwrap_or(l))
        .collect();
    if lines.first().is_some_and(|l| is_from_line(l)) {
        lines.remove(0);
    }
    let blank = lines
        .iter()
        .position(|l| l.is_empty())
        .unwrap_or(lines.len());
    let headers = unfold(&lines[..blank]);
    let mut body = lines.get(blank + 1..).unwrap_or(&[]).to_vec();

    let mut author = None;
    let mut subject = String::new();
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("from") {
            author = Some(decode_words(value));
        } else if name.eq_ignore_ascii_case("subject") {
            subject = clean_subject(&decode_words(value));
        } else if name.eq_ignore_ascii_case("content-transfer-encoding") {
            let enc = value.trim().to_ascii_lowercase();
            if enc != "7bit" && enc != "8bit" {
                return Err(MailError::Encoding(enc));
            }
        }
    }
    // A `From:` line at the very start of the body names the author, as
    // `git am` reads it.
    if let Some(first) = body.first()
        && let Some(v) = first.strip_prefix(b"From: ")
    {
        author = Some(decode_words(&String::from_utf8_lossy(v)));
        body.remove(0);
        if body.first().is_some_and(|l| l.is_empty()) {
            body.remove(0);
        }
    }
    let author = author
        .filter(|a| !a.trim().is_empty())
        .ok_or(MailError::NoAuthor)?;

    let end = (0..body.len())
        .find(|&i| {
            let l = body[i];
            l.trim_ascii_end() == b"---"
                || l.starts_with(b"diff --git ")
                || (l.starts_with(b"--- ")
                    && body.get(i + 1).is_some_and(|n| n.starts_with(b"+++ ")))
        })
        .unwrap_or(body.len());
    let text: Vec<String> = body[..end]
        .iter()
        .map(|l| String::from_utf8_lossy(l).trim_end().to_owned())
        .collect();
    let first = text
        .iter()
        .position(|l| !l.is_empty())
        .unwrap_or(text.len());
    let last = text
        .iter()
        .rposition(|l| !l.is_empty())
        .map_or(first, |i| i + 1);
    let rest = text[first..last.max(first)].join("\n");
    let message = if rest.is_empty() {
        subject
    } else {
        format!("{subject}\n\n{rest}")
    };

    let mut patch_text = Vec::new();
    for l in &body[end..] {
        patch_text.extend_from_slice(l);
        patch_text.push(b'\n');
    }
    patch::parse(&patch_text).map_err(MailError::Patch)?;
    Ok(Mail {
        author,
        message,
        patch: patch_text,
    })
}

/// The headers, with each continuation line joined to the line before.
fn unfold(lines: &[&[u8]]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for raw in lines {
        let line = String::from_utf8_lossy(raw);
        let line = line.trim_end_matches('\r');
        if line.starts_with([' ', '\t']) {
            if let Some((_, v)) = out.last_mut() {
                v.push(' ');
                v.push_str(line.trim());
            }
        } else if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    out
}

/// The subject without a leading `[...]` group, such as `[PATCH 2/3]`, or
/// `Re:`.
fn clean_subject(s: &str) -> String {
    let mut s = s.trim();
    loop {
        if s.starts_with('[')
            && let Some(end) = s.find(']')
        {
            s = s[end + 1..].trim_start();
        } else if s.len() >= 3 && s[..3].eq_ignore_ascii_case("re:") {
            s = s[3..].trim_start();
        } else {
            return s.to_owned();
        }
    }
}

/// Decode the RFC 2047 encoded words of a header value. Space between two
/// encoded words is dropped. A word in a charset other than UTF-8 or ASCII,
/// or one that does not decode, stays as written.
fn decode_words(value: &str) -> String {
    let mut out = String::new();
    let mut last_encoded = false;
    for (i, token) in value.split(' ').enumerate() {
        let decoded = decode_word(token);
        if i > 0 && !(last_encoded && decoded.is_some()) {
            out.push(' ');
        }
        last_encoded = decoded.is_some();
        out.push_str(decoded.as_deref().unwrap_or(token));
    }
    out
}

fn decode_word(token: &str) -> Option<String> {
    let inner = token.strip_prefix("=?")?.strip_suffix("?=")?;
    let mut parts = inner.splitn(3, '?');
    let charset = parts.next()?;
    let enc = parts.next()?;
    let text = parts.next()?;
    if !charset.eq_ignore_ascii_case("utf-8") && !charset.eq_ignore_ascii_case("us-ascii") {
        return None;
    }
    let bytes = match enc {
        "B" | "b" => base64(text.as_bytes())?,
        "Q" | "q" => quoted(text.as_bytes())?,
        _ => return None,
    };
    String::from_utf8(bytes).ok()
}

fn quoted(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'_' => out.push(b' '),
            b'=' => {
                let hex = std::str::from_utf8(s.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    Some(out)
}

fn base64(s: &[u8]) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let s = s
        .strip_suffix(b"==")
        .or_else(|| s.strip_suffix(b"="))
        .unwrap_or(s);
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s {
        acc = (acc << 6) | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const DIFF: &str = "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b\n";

    fn mail(headers: &str, body: &str) -> Vec<u8> {
        format!("From 1234 Mon Sep 17 00:00:00 2001\n{headers}\n{body}").into_bytes()
    }

    #[test]
    fn a_mailbox_splits_at_from_lines_with_a_date() {
        let one = mail("From: A <a@x>\nSubject: one\n", &format!("---\n{DIFF}"));
        let mut text = one.clone();
        text.extend_from_slice(b"From someone who wrote a sentence\n");
        text.extend_from_slice(&one);
        let mails = split(&text);
        assert_eq!(mails.len(), 2);
        assert!(mails[0].ends_with(b"From someone who wrote a sentence\n"));
        assert_eq!(split(DIFF.as_bytes()), vec![DIFF.as_bytes()]);
    }

    #[test]
    fn author_subject_and_body() {
        let m = parse(&mail(
            "From: =?UTF-8?q?Bj=C3=B6rn?= <b@x>\nSubject: [PATCH 2/3] Re: Fix\n =?UTF-8?B?w6k=?=\n",
            &format!("\nWhy it matters.\n\n---\n f | 2 +-\n\n{DIFF}-- \n2.40\n"),
        ))
        .unwrap();
        assert_eq!(m.author, "Björn <b@x>");
        assert_eq!(m.message, "Fix é\n\nWhy it matters.");
        assert_eq!(patch::parse(&m.patch).unwrap().len(), 1);
    }

    #[test]
    fn an_in_body_from_overrides_the_header() {
        let m = parse(&mail(
            "From: A <a@x>\nSubject: s\n",
            &format!("From: B <b@x>\n\n{DIFF}"),
        ))
        .unwrap();
        assert_eq!((m.author.as_str(), m.message.as_str()), ("B <b@x>", "s"));
    }

    #[test]
    fn refusals() {
        let enc = mail(
            "From: A <a@x>\nSubject: s\nContent-Transfer-Encoding: base64\n",
            DIFF,
        );
        assert_eq!(parse(&enc), Err(MailError::Encoding("base64".to_owned())));
        let none = parse(&mail("From: A <a@x>\nSubject: s\n", "text only\n")).unwrap_err();
        assert!(none.to_string().contains("no patch"), "{none}");
        assert_eq!(parse(&mail("Subject: s\n", DIFF)), Err(MailError::NoAuthor));
    }

    proptest::proptest! {
        #[test]
        fn split_and_parse_never_panic(text in proptest::collection::vec(proptest::num::u8::ANY, 0..400)) {
            let mails = split(&text);
            let total: usize = mails.iter().map(|m| m.len()).sum();
            proptest::prop_assert!(total <= text.len());
            for m in mails {
                let _ = parse(m);
            }
        }
    }
}
