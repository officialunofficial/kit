//! Every domain-separation tag, magic and predicate URI has one unique value.
//!
//! The test scans the production source of every workspace crate for two
//! kinds of definition:
//!
//! * `const` and `static` items that define such a value. An item may span
//!   several lines.
//! * Inline literals: a tag-shaped literal passed to a hash `update` or
//!   `derive_key` call, and a magic-shaped byte literal outside any item.
//!
//! It fails when two definitions share a value, because a shared value lets
//! a signature or hash made for one purpose verify for another. An inline
//! literal that repeats the value of an item is such a duplicate. Give the
//! value one named item and use that item everywhere.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// One definition of a tag, a magic or a predicate URI.
#[derive(Debug, PartialEq, Eq)]
struct Definition {
    place: String,
    value: String,
}

const PREDICATE_PREFIX: &str = "https://kit.storage/spec/predicate/";

/// The calls whose first argument is a hash or key-derivation context.
const HASH_CALLS: [&str; 3] = ["update(", "derive_key(", "new_derive_key("];

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "tests" {
                source_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

/// Returns the raw text of the string literal that starts at the first quote
/// of `rest`, with `\x00` folded into `\0` so both spellings of a zero byte
/// compare equal, and the number of bytes consumed up to its closing quote.
fn first_literal(rest: &str) -> Option<(String, usize)> {
    let start = rest.find('"')? + 1;
    let mut end = start;
    let bytes = rest.as_bytes();
    while end < bytes.len() {
        match bytes[end] {
            b'\\' => end += 2,
            b'"' => return Some((rest[start..end].replace("\\x00", "\\0"), end + 1)),
            _ => end += 1,
        }
    }
    None
}

/// A value that looks like a domain-separation tag or a predicate URI.
fn tag_shaped(value: &str) -> bool {
    value.starts_with("kit.")
        || value.starts_with("kit-")
        || value.starts_with(PREDICATE_PREFIX)
        || value.strip_suffix("\\0").is_some_and(|body| {
            !body.is_empty()
                && body
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".:_-/".contains(&b))
        })
}

/// A value that looks like a magic: `K`, then up to seven uppercase
/// letters or digits, then an optional version or zero byte.
fn magic_shaped(value: &str) -> bool {
    let body = value
        .strip_suffix("\\0")
        .or_else(|| {
            value
                .rfind("\\x")
                .filter(|&i| value.len() == i + 4)
                .map(|i| &value[..i])
        })
        .unwrap_or(value);
    (4..=8).contains(&body.len())
        && body.starts_with('K')
        && body
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// The production part of a source file: everything before the `#[cfg(test)]`
/// line of the test module. A `#[cfg(test)]` line counts as that marker when
/// the next line that is not an attribute starts a module. Line comments are
/// blanked, so line numbers stay.
fn production(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::new();
    for (index, line) in lines.iter().enumerate() {
        if *line == "#[cfg(test)]" {
            let next = lines[index + 1..]
                .iter()
                .find(|l| !l.trim_start().starts_with("#["));
            if next.is_some_and(|l| l.trim_start().starts_with("mod ")) {
                break;
            }
        }
        if !line.trim_start().starts_with("//") {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn item_start(line: &str) -> Option<&str> {
    let line = line.trim_start();
    let line = match line.strip_prefix("pub(") {
        Some(rest) => rest.split_once(") ")?.1,
        None => line.strip_prefix("pub ").unwrap_or(line),
    };
    line.strip_prefix("const ")
        .or_else(|| line.strip_prefix("static "))
        .filter(|rest| !rest.starts_with("fn "))
}

/// Whether an item body holds its terminating `;`, which follows the `=`.
fn complete(body: &str) -> bool {
    body.split_once('=')
        .is_some_and(|(_, value)| value.contains(';'))
}

/// Splits the production text into the `const` and `static` items, which end
/// at their first `;`, and the remaining text. The remaining text keeps its
/// line numbers.
fn split_items(text: &str) -> (Vec<(usize, String)>, String) {
    let mut items = Vec::new();
    let mut rest = String::new();
    let mut open: Option<(usize, String)> = None;
    for (index, line) in text.lines().enumerate() {
        if let Some((start, mut body)) = open.take() {
            body.push('\n');
            body.push_str(line);
            if complete(&body) {
                items.push((start, body));
            } else {
                open = Some((start, body));
            }
            rest.push('\n');
        } else if let Some(after) = item_start(line) {
            if complete(after) {
                items.push((index + 1, after.to_owned()));
            } else {
                open = Some((index + 1, after.to_owned()));
            }
            rest.push('\n');
        } else {
            rest.push_str(line);
            rest.push('\n');
        }
    }
    (items, rest)
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Finds the definitions in `text`: the named items, then the inline
/// literals.
fn definitions(place: &str, text: &str) -> Vec<Definition> {
    let (items, outside) = split_items(&production(text));
    let mut found = Vec::new();
    for (line, item) in items {
        let Some((head, rest)) = item.split_once('=') else {
            continue;
        };
        let name = head.split(':').next().unwrap().trim();
        let Some((value, _)) = first_literal(rest) else {
            continue;
        };
        let named = ["MAGIC", "DOMAIN", "PREDICATE"]
            .iter()
            .any(|word| name.contains(word));
        if named || tag_shaped(&value) || magic_shaped(&value) {
            found.push(Definition {
                place: format!("{place}:{line}::{name}"),
                value,
            });
        }
    }
    // A tag-shaped literal in a hash call.
    for call in HASH_CALLS {
        let mut from = 0;
        while let Some(at) = outside[from..].find(call) {
            let after = from + at + call.len();
            let arg = outside[after..].trim_start_matches(|c: char| c.is_whitespace() || c == '&');
            let arg_at = outside.len() - arg.len();
            from = after;
            let arg = arg.strip_prefix('b').unwrap_or(arg);
            if !arg.starts_with('"') {
                continue;
            }
            if let Some((value, _)) = first_literal(arg).filter(|(value, _)| tag_shaped(value)) {
                found.push(Definition {
                    place: format!("{place}:{}::inline", line_of(&outside, arg_at)),
                    value,
                });
            }
        }
    }
    // A magic-shaped byte literal outside any item.
    let mut from = 0;
    while let Some(at) = outside[from..].find("b\"") {
        let start = from + at;
        // `b"` that ends an identifier, such as `sub"`, is not a byte literal.
        let boundary = outside[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
        let Some((value, used)) = first_literal(&outside[start..]) else {
            break;
        };
        from = start + used;
        if boundary && magic_shaped(&value) {
            found.push(Definition {
                place: format!("{place}:{}::inline", line_of(&outside, start)),
                value,
            });
        }
    }
    found
}

/// Returns each value that more than one definition uses, with the places.
fn duplicates(defs: &[Definition]) -> Vec<(String, Vec<String>)> {
    let mut by_value: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for def in defs {
        by_value
            .entry(def.value.as_str())
            .or_default()
            .push(def.place.clone());
    }
    by_value
        .into_iter()
        .filter(|(_, places)| places.len() > 1)
        .map(|(value, places)| (value.to_owned(), places))
        .collect()
}

fn workspace_definitions() -> Vec<Definition> {
    let mut files = Vec::new();
    for entry in fs::read_dir(crates_dir()).unwrap() {
        let src = entry.unwrap().path().join("src");
        if src.is_dir() {
            source_files(&src, &mut files);
        }
    }
    files.sort();
    let mut defs = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        let place = file
            .strip_prefix(crates_dir())
            .unwrap()
            .display()
            .to_string();
        defs.extend(definitions(&place, &text));
    }
    defs
}

#[test]
fn no_two_workspace_definitions_share_a_tag_magic_or_predicate() {
    let defs = workspace_definitions();
    // The scan must see the known values, or it checks nothing.
    for expected in [
        "kit.tree\\0",
        "kit-write:v2",
        "kit-sparse-filter-v2\\0",
        "kit-fetch-head-v1",
        "kit-history-transaction-v1",
        "kit-url-token:v1",
        "KIT\\0",
        "KITKSV1\\0",
        "KOB1",
        "KIDX",
        "KDPB",
        "KDSP",
        "KCLM",
        "KSP1",
        "KSPC",
        "KPKL",
        "KSTS",
        "KHAN\\x01",
        "KSCR\\x02",
    ] {
        assert!(
            defs.iter().any(|def| def.value == expected),
            "the scan did not find {expected}"
        );
    }
    assert_eq!(duplicates(&defs), Vec::new());
}

#[test]
fn the_duplicate_check_reports_a_shared_value() {
    let source = "pub const A_DOMAIN: &[u8] = b\"kit.one\\x00\";\n\
                  const B_DOMAIN: &[u8] = b\"kit.one\\0\";\n\
                  const C_MAGIC: [u8; 4] = *b\"KXXX\";\n\
                  const D_MAGIC: [u8; 4] = *b\"KYYY\";\n";
    let defs = definitions("x.rs", source);
    assert_eq!(defs.len(), 4);
    assert_eq!(
        duplicates(&defs),
        vec![(
            "kit.one\\0".to_owned(),
            vec!["x.rs:1::A_DOMAIN".to_owned(), "x.rs:2::B_DOMAIN".to_owned()]
        )]
    );
}

#[test]
fn a_multi_line_item_is_scanned() {
    let source = "pub const A_DOMAIN: &[u8] =\n    b\"kit.two\\0\";\n\
                  pub const B: &str =\n    \"kit-two-v1\";\n\
                  const C: &str = \"kit-two-v1\";\n";
    let defs = definitions("x.rs", source);
    assert_eq!(defs.len(), 3);
    assert_eq!(duplicates(&defs).len(), 1);
}

#[test]
fn an_inline_hash_literal_is_scanned() {
    let source = "const A: &[u8] = b\"kit-three-v1\";\n\
                  fn f(h: &mut H) {\n\
                  \x20   h.update(b\"kit-three-v1\");\n\
                  \x20   h.update(b\"abc\");\n\
                  \x20   h.update(b\"kit-four-v1\\0\");\n\
                  }\n";
    let defs = definitions("x.rs", source);
    assert_eq!(defs.len(), 3);
    assert_eq!(
        duplicates(&defs),
        vec![(
            "kit-three-v1".to_owned(),
            vec!["x.rs:1::A".to_owned(), "x.rs:3::inline".to_owned()]
        )]
    );
}

#[test]
fn an_inline_magic_is_scanned() {
    let source = "pub const MAGIC: [u8; 4] = *b\"KXXX\";\n\
                  fn f(b: &[u8]) -> bool {\n\
                  \x20   b.starts_with(b\"KXXX\") || b.starts_with(b\"abcd\")\n\
                  }\n";
    let defs = definitions("x.rs", source);
    assert_eq!(defs.len(), 2);
    assert_eq!(duplicates(&defs).len(), 1);
}

#[test]
fn test_code_after_the_test_marker_is_not_scanned() {
    let source = "const A_DOMAIN: &str = \"kit-a:v1\";\n\
                  #[cfg(test)]\n\
                  #[allow(clippy::unwrap_used)]\n\
                  mod tests {\n\
                  const B_DOMAIN: &str = \"kit-a:v1\";\n\
                  }\n";
    assert_eq!(definitions("x.rs", source).len(), 1);
}

#[test]
fn a_test_only_item_does_not_end_the_scan() {
    let source = "#[cfg(test)]\n\
                  thread_local! { static X: u8 = 0; }\n\
                  const A_DOMAIN: &str = \"kit-a:v1\";\n";
    assert_eq!(definitions("x.rs", source).len(), 1);
}
