//! Every domain-separation tag, magic and predicate URI has one unique value.
//!
//! The test scans the production source of every workspace crate for
//! `const` items that define such a value. It fails when two items share a
//! value, because a shared value lets a signature or hash made for one
//! purpose verify for another.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// One `const` item that defines a tag, a magic or a predicate URI.
#[derive(Debug, PartialEq, Eq)]
struct Definition {
    place: String,
    value: String,
}

const PREDICATE_PREFIX: &str = "https://kit.storage/spec/predicate/";

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

/// Returns the raw text of the first string literal in `rest`, with `\x00`
/// folded into `\0` so both spellings of a zero byte compare equal.
fn first_literal(rest: &str) -> Option<String> {
    let start = rest.find('"')? + 1;
    let mut end = start;
    let bytes = rest.as_bytes();
    while end < bytes.len() {
        match bytes[end] {
            b'\\' => end += 2,
            b'"' => return Some(rest[start..end].replace("\\x00", "\\0")),
            _ => end += 1,
        }
    }
    None
}

/// Finds the `const` items in `text` that define a tag, a magic or a
/// predicate URI. Code after the first `#[cfg(test)]` line is test code.
fn definitions(place: &str, text: &str) -> Vec<Definition> {
    let mut found = Vec::new();
    for line in text.lines() {
        if line == "#[cfg(test)]" {
            break;
        }
        let line = line.trim_start();
        if line.starts_with("//") {
            continue;
        }
        let Some(after) = line
            .strip_prefix("pub const ")
            .or_else(|| line.strip_prefix("pub(crate) const "))
            .or_else(|| line.strip_prefix("const "))
        else {
            continue;
        };
        let Some((head, rest)) = after.split_once('=') else {
            continue;
        };
        let name = head.split(':').next().unwrap().trim();
        let Some(value) = first_literal(rest) else {
            continue;
        };
        let named = ["MAGIC", "DOMAIN", "PREDICATE"]
            .iter()
            .any(|word| name.contains(word));
        let shaped = value.starts_with("kit.")
            || value.starts_with("kit-")
            || value.starts_with(PREDICATE_PREFIX);
        if named || shaped {
            found.push(Definition {
                place: format!("{place}::{name}"),
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
fn no_two_workspace_constants_share_a_tag_magic_or_predicate() {
    let defs = workspace_definitions();
    // The scan must see the known values, or it checks nothing.
    for expected in ["kit.tree\\0", "kit-write:v2", "KIT\\0", "KITKSV1\\0"] {
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
                  const C_MAGIC: [u8; 4] = *b\"MKXX\";\n\
                  const D_MAGIC: [u8; 4] = *b\"MKYY\";\n";
    let defs = definitions("x.rs", source);
    assert_eq!(defs.len(), 4);
    assert_eq!(
        duplicates(&defs),
        vec![(
            "kit.one\\0".to_owned(),
            vec!["x.rs::A_DOMAIN".to_owned(), "x.rs::B_DOMAIN".to_owned()]
        )]
    );
}

#[test]
fn test_code_after_the_test_marker_is_not_scanned() {
    let source = "const A_DOMAIN: &str = \"kit-a:v1\";\n\
                  #[cfg(test)]\n\
                  const B_DOMAIN: &str = \"kit-a:v1\";\n";
    assert_eq!(definitions("x.rs", source).len(), 1);
}
