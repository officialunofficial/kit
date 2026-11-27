//! `alias.<name>` in the user-scoped config names kit arguments that run
//! when `<name>` is typed as a command.
//!
//! Invariants:
//! - Equivalence: an alias runs exactly as its expansion with the same
//!   trailing arguments (same stdout, stderr and exit code).
//! - Repo cannot set: an `alias.*` key in `.kit/config` or a `-c` override
//!   is refused, whatever the value.
//! - Built-ins win: no alias changes what a built-in name does.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::process::Output;

use common::Repo;
use proptest::prelude::*;

fn repo() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "first");
    repo.commit_file("b.txt", b"two\n", "second");
    repo.write("a.txt", b"changed\n");
    repo
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn same(a: &Output, b: &Output) {
    assert_eq!(a.status.code(), b.status.code());
    assert_eq!(text(&a.stdout), text(&b.stdout));
    assert_eq!(text(&a.stderr), text(&b.stderr));
}

#[test]
fn an_alias_runs_its_expansion_with_trailing_arguments() {
    let repo = repo();
    let set = repo.ok(&["config", "alias.st", "status -s"]);
    assert!(text(&set.stderr).contains("user-scoped"), "{set:?}");
    same(&repo.run(&["st"]), &repo.run(&["status", "-s"]));
    repo.ok(&["config", "alias.lg", "log --oneline"]);
    same(
        &repo.run(&["lg", "-n", "1"]),
        &repo.run(&["log", "--oneline", "-n", "1"]),
    );
}

#[test]
fn quotes_keep_an_argument_together() {
    let repo = repo();
    repo.ok(&["config", "alias.cm", "commit -am \"two words\""]);
    repo.ok(&["cm"]);
    let log = text(&repo.ok(&["log", "--oneline", "-n", "1"]).stdout);
    assert!(log.trim_end().ends_with(" two words"), "{log}");
}

#[test]
fn an_alias_works_outside_a_repository() {
    let repo = Repo::new();
    repo.ok(&["config", "alias.v", "version"]);
    let elsewhere = tempfile::tempdir().unwrap();
    let out = common::kit_env(elsewhere.path(), repo.xdg(), &["v"], &[]);
    assert!(out.status.success(), "{out:?}");
    assert!(text(&out.stdout).starts_with("kit "), "{out:?}");
}

#[test]
fn a_repository_config_cannot_define_an_alias() {
    let repo = repo();
    let config = repo.kit_dir().join("config");
    let mut body = std::fs::read_to_string(&config).unwrap_or_default();
    body.push_str("alias.st = status -s\n");
    std::fs::write(&config, body).unwrap();
    let out = repo.run(&["st"]);
    assert_eq!(out.status.code(), Some(64), "{out:?}");
    let err = text(&out.stderr);
    assert!(err.contains("unknown command 'st'"), "{err}");
    // Any command that reads config names the dropped key.
    let shown = repo.run(&["config"]);
    assert!(text(&shown.stderr).contains("alias.st"), "{shown:?}");
    let local = repo.run(&["config", "--local", "alias.st", "status"]);
    assert_eq!(local.status.code(), Some(78), "{local:?}");
}

#[test]
fn a_command_line_override_cannot_define_an_alias() {
    let repo = repo();
    let out = repo.run(&["-c", "alias.st=status", "st"]);
    assert_eq!(out.status.code(), Some(64), "{out:?}");
    assert!(text(&out.stderr).contains("alias.st"), "{out:?}");
}

#[test]
fn a_built_in_name_wins_over_an_alias() {
    let repo = repo();
    let before = repo.run(&["log", "--oneline"]);
    let set = repo.ok(&["config", "alias.log", "status"]);
    assert!(text(&set.stderr).contains("built-in"), "{set:?}");
    let after = repo.run(&["log", "--oneline"]);
    assert_eq!(text(&after.stdout), text(&before.stdout));
    assert_eq!(after.status.code(), before.status.code());
}

#[test]
fn an_alias_of_an_alias_is_an_error() {
    let repo = repo();
    repo.ok(&["config", "alias.b", "status"]);
    repo.ok(&["config", "alias.a", "b -s"]);
    let out = repo.run(&["a"]);
    assert_eq!(out.status.code(), Some(64), "{out:?}");
    assert!(text(&out.stderr).contains("alias"), "{out:?}");
}

#[test]
fn a_shell_alias_is_refused() {
    let repo = repo();
    let out = repo.run(&["config", "alias.x", "!echo hi"]);
    assert_eq!(out.status.code(), Some(78), "{out:?}");
    assert_eq!(repo.run(&["x"]).status.code(), Some(64));
}

#[test]
fn get_regexp_lists_aliases_and_unset_removes_one() {
    let repo = repo();
    repo.ok(&["config", "alias.st", "status -s"]);
    repo.ok(&["config", "alias.lg", "log --oneline"]);
    let listed = text(&repo.ok(&["config", "--get-regexp", "alias."]).stdout);
    assert_eq!(listed, "alias.lg log --oneline\nalias.st status -s\n");
    assert_eq!(
        text(&repo.ok(&["config", "alias.st"]).stdout).trim(),
        "status -s"
    );
    repo.ok(&["config", "--unset", "alias.st"]);
    assert_eq!(repo.run(&["st"]).status.code(), Some(64));
    let none = repo.run(&["config", "--get-regexp", "^alias\\.st$"]);
    assert_eq!(none.status.code(), Some(1), "{none:?}");
}

/// Read-only expansions whose output is deterministic for one repository.
const EXPANSIONS: &[&str] = &[
    "status",
    "status -s",
    "log --oneline",
    "branch --list",
    "rev-parse HEAD",
    "diff --stat",
    "show --stat HEAD",
];

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    #[test]
    fn an_alias_equals_its_expansion(
        name in "zz[a-z]{1,4}",
        pick in 0..EXPANSIONS.len(),
        trailing in prop::sample::select(vec![vec![], vec!["-n", "1"], vec!["--", "a.txt"]]),
    ) {
        static REPO: std::sync::OnceLock<Repo> = std::sync::OnceLock::new();
        let repo = REPO.get_or_init(repo);
        let expansion = EXPANSIONS[pick];
        repo.ok(&["config", &format!("alias.{name}"), expansion]);
        let mut via_alias = vec![name.as_str()];
        via_alias.extend(trailing.iter().copied());
        let mut direct: Vec<&str> = expansion.split(' ').collect();
        direct.extend(trailing.iter().copied());
        let (a, b) = (repo.run(&via_alias), repo.run(&direct));
        prop_assert_eq!(a.status.code(), b.status.code());
        prop_assert_eq!(text(&a.stdout), text(&b.stdout));
        prop_assert_eq!(text(&a.stderr), text(&b.stderr));
    }
}
