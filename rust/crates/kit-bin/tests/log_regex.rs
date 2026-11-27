//! `kit log --grep` and `--author` take regular expressions, as git does,
//! with `-F`, `-i`, `--all-match` and `--invert-grep`.
//!
//! Invariants:
//! - Literal agreement: a pattern with no regex metacharacters selects the
//!   same commits as a regex and with `-F`.
//! - Invert: `--invert-grep` selects the complement of `--grep` in the walk.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::BTreeSet;

use common::Repo;
use proptest::prelude::*;

/// Subjects, oldest first, and the author of each.
const HISTORY: &[(&str, &str)] = &[
    ("fix: crash on empty input", "alice"),
    ("feat: add the export", "bob"),
    ("docs: fix a typo", "alice"),
    ("Fix: capitalised subject", "carol"),
    ("release v1.2", "bob"),
    ("release v1x2", "carol"),
];

fn history() -> Repo {
    let repo = Repo::new();
    for (i, (subject, author)) in HISTORY.iter().enumerate() {
        repo.write("f.txt", format!("{i}\n").as_bytes());
        repo.ok(&["add", "f.txt"]);
        repo.ok(&[
            "commit",
            "-m",
            subject,
            "--author",
            &format!("opaque:{author}"),
        ]);
    }
    repo
}

/// The subjects that `kit log --oneline <args>` prints.
fn subjects(repo: &Repo, args: &[&str]) -> BTreeSet<String> {
    let mut all = vec!["log", "--oneline"];
    all.extend_from_slice(args);
    String::from_utf8_lossy(&repo.ok(&all).stdout)
        .lines()
        .map(|l| l.split_once(' ').unwrap().1.to_owned())
        .collect()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn grep_is_a_regex_anchored_per_line() {
    let repo = history();
    assert_eq!(
        subjects(&repo, &["--grep", "^fix"]),
        set(&["fix: crash on empty input"])
    );
    assert_eq!(
        subjects(&repo, &["--grep", "v1.2"]),
        set(&["release v1.2", "release v1x2"])
    );
}

#[test]
fn fixed_strings_take_the_pattern_literally() {
    let repo = history();
    assert_eq!(
        subjects(&repo, &["-F", "--grep", "v1.2"]),
        set(&["release v1.2"])
    );
    assert_eq!(
        subjects(&repo, &["--fixed-strings", "--grep", "v1.2"]),
        set(&["release v1.2"])
    );
}

#[test]
fn ignore_case_applies_to_grep() {
    let repo = history();
    assert_eq!(
        subjects(&repo, &["-i", "--grep", "^fix"]),
        set(&["fix: crash on empty input", "Fix: capitalised subject"])
    );
    assert_eq!(
        subjects(&repo, &["--regexp-ignore-case", "--grep", "^FIX:"]),
        set(&["fix: crash on empty input", "Fix: capitalised subject"])
    );
}

#[test]
fn several_greps_match_any_unless_all_match() {
    let repo = history();
    assert_eq!(
        subjects(&repo, &["--grep", "crash", "--grep", "typo"]),
        set(&["fix: crash on empty input", "docs: fix a typo"])
    );
    assert_eq!(
        subjects(&repo, &["--all-match", "--grep", "fix", "--grep", "typo"]),
        set(&["docs: fix a typo"])
    );
}

#[test]
fn invert_grep_keeps_the_commits_that_do_not_match() {
    let repo = history();
    assert_eq!(
        subjects(&repo, &["--invert-grep", "--grep", "fix"]),
        set(&[
            "feat: add the export",
            "Fix: capitalised subject",
            "release v1.2",
            "release v1x2",
        ])
    );
}

#[test]
fn author_is_a_regex_and_repeats_as_or() {
    let repo = history();
    assert_eq!(
        subjects(&repo, &["--author", "^opaque:(alice|carol)$"]),
        set(&[
            "fix: crash on empty input",
            "docs: fix a typo",
            "Fix: capitalised subject",
            "release v1x2",
        ])
    );
    assert_eq!(
        subjects(&repo, &["--author", "bob", "--author", "carol"]).len(),
        4
    );
    assert_eq!(
        subjects(&repo, &["--author", "bob", "--grep", "^release"]),
        set(&["release v1.2"])
    );
}

#[test]
fn an_invalid_pattern_is_a_usage_error() {
    let repo = history();
    for args in [&["log", "--grep", "("][..], &["log", "--author", "[a"][..]] {
        let out = repo.run(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {out:?}");
    }
}

#[test]
fn match_flags_without_a_pattern_are_a_usage_error() {
    let repo = history();
    for flag in ["--all-match", "--invert-grep"] {
        let out = repo.run(&["log", flag]);
        assert_eq!(out.status.code(), Some(64), "{flag}: {out:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    #[test]
    fn literal_patterns_agree_and_invert_is_the_complement(pattern in "[a-z0-9 ]{1,3}") {
        static REPO: std::sync::OnceLock<Repo> = std::sync::OnceLock::new();
        let repo = REPO.get_or_init(history);
        let regex = subjects(repo, &["--grep", &pattern]);
        let fixed = subjects(repo, &["-F", "--grep", &pattern]);
        prop_assert_eq!(&regex, &fixed);
        let inverted = subjects(repo, &["--invert-grep", "--grep", &pattern]);
        let all = subjects(repo, &[]);
        prop_assert!(regex.is_disjoint(&inverted));
        prop_assert_eq!(regex.union(&inverted).cloned().collect::<BTreeSet<_>>(), all);
    }
}
