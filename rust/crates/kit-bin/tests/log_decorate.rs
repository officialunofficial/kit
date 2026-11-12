//! `kit log --decorate`: the refs that name a commit follow its id.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use common::Repo;

fn stdout(repo: &Repo, args: &[&str]) -> String {
    String::from_utf8(repo.ok(args).stdout).unwrap()
}

/// The text after the id on the first `--oneline` line, up to the title.
fn first_decoration(repo: &Repo, args: &[&str]) -> String {
    let mut all = vec!["log", "--oneline", "--decorate", "-n1"];
    all.extend_from_slice(args);
    let out = stdout(repo, &all);
    let line = out.lines().next().unwrap();
    let rest = line.split_once(' ').unwrap().1;
    let end = rest.find(')').map_or(0, |i| i + 1);
    rest[..end].to_owned()
}

/// `main` has `one`, `two`. The tag `v1` and the remote-tracking ref
/// `origin/main` name `two`. `topic` names `one`.
fn decorated() -> (Repo, Repo) {
    let repo = Repo::new();
    let remote = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.ok(&["branch", "topic"]);
    repo.commit_file("b.txt", b"two\n", "two");
    repo.ok(&["tag", "v1"]);
    let url = format!("kit+file://{}", remote.path().display());
    repo.ok(&["remote", "add", "origin", &url]);
    repo.ok(&["push", "origin", "main:main"]);
    (repo, remote)
}

#[test]
fn oneline_lists_head_the_tags_and_the_remote_refs_after_the_id() {
    let (repo, _remote) = decorated();
    let out = stdout(&repo, &["log", "--oneline", "--decorate"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    let (id, rest) = lines[0].split_once(' ').unwrap();
    assert_eq!(id.len(), 7);
    assert_eq!(rest, "(HEAD -> main, tag: v1, origin/main) two");
    assert!(lines[1].ends_with(" (topic) one"), "{out}");
}

#[test]
fn the_default_format_puts_the_decoration_on_the_commit_line() {
    let (repo, _remote) = decorated();
    let out = stdout(&repo, &["log", "--decorate"]);
    let line = out.lines().next().unwrap();
    assert!(line.starts_with("commit "), "{line}");
    assert!(
        line.ends_with(" (HEAD -> main, tag: v1, origin/main)"),
        "{line}"
    );
    let second = out.lines().find(|l| l.contains("topic")).unwrap();
    assert!(second.ends_with(" (topic)"), "{second}");
}

#[test]
fn a_commit_without_a_ref_has_no_decoration() {
    let (repo, _remote) = decorated();
    repo.commit_file("c.txt", b"three\n", "three");
    let out = stdout(&repo, &["log", "--oneline", "--decorate"]);
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].ends_with(" (HEAD -> main) three"), "{out}");
    assert!(lines[1].ends_with(" (tag: v1, origin/main) two"), "{out}");
    // A commit that no ref names prints no parentheses.
    repo.commit_file("d.txt", b"four\n", "four");
    let out = stdout(&repo, &["log", "--oneline", "--decorate"]);
    assert!(out.lines().any(|l| l.ends_with(" three")), "{out}");
    assert!(
        !out.lines()
            .any(|l| l.ends_with(" three") && l.contains('('))
    );
}

#[test]
fn a_detached_head_is_decorated_with_head_alone() {
    let (repo, _remote) = decorated();
    let id = stdout(&repo, &["rev-parse", "topic"]);
    repo.ok(&["checkout", id.trim()]);
    assert_eq!(first_decoration(&repo, &[]), "(HEAD, topic)");
}

#[test]
fn an_annotated_tag_decorates_the_commit_it_names() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.ok(&["tag", "-a", "rel", "-m", "release"]);
    assert_eq!(first_decoration(&repo, &[]), "(HEAD -> main, tag: rel)");
}

#[test]
fn unusual_but_legal_ref_names_print_as_they_are() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    repo.ok(&["branch", "feat/a..b_c-d.e"]);
    repo.ok(&["tag", "v1.0-rc.1_x"]);
    assert_eq!(
        first_decoration(&repo, &[]),
        "(HEAD -> main, feat/a..b_c-d.e, tag: v1.0-rc.1_x)"
    );
}

#[test]
fn a_ref_name_with_control_characters_never_reaches_the_terminal() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "one");
    let id = stdout(&repo, &["rev-parse", "HEAD"]);
    for dir in ["refs/heads", "refs/tags"] {
        let path = repo.kit_dir().join(dir).join("evil\x1b]0;x\x07\u{202e}");
        std::fs::write(path, format!("{}\n", id.trim())).unwrap();
    }
    let out = repo.ok(&["log", "--decorate", "--oneline"]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        !text.bytes().any(|b| b < 0x20 && b != b'\n'),
        "control byte in {text:?}"
    );
    assert!(!text.contains('\u{202e}'), "{text:?}");
    assert!(text.contains("(HEAD -> main) one"), "{text:?}");
}

#[test]
fn decorate_combines_with_all_and_a_revision() {
    let (repo, _remote) = decorated();
    let all = stdout(&repo, &["log", "--oneline", "--decorate", "--all"]);
    assert!(all.contains("(HEAD -> main, tag: v1, origin/main) two"));
    let one = stdout(&repo, &["log", "--oneline", "--decorate", "topic"]);
    assert!(one.trim_end().ends_with("(topic) one"), "{one}");
}

#[test]
fn decorate_follows_patch_output() {
    let (repo, _remote) = decorated();
    let out = stdout(&repo, &["log", "--decorate", "-p", "-n1"]);
    assert!(out.starts_with("commit "), "{out}");
    assert!(
        out.lines().next().unwrap().contains("(HEAD -> main"),
        "{out}"
    );
    assert!(out.contains("diff --git a/b.txt b/b.txt"), "{out}");
}

#[test]
fn decorate_is_off_by_default() {
    let (repo, _remote) = decorated();
    let out = stdout(&repo, &["log", "--oneline"]);
    assert!(!out.contains('('), "{out}");
}

#[test]
fn decorate_with_json_is_a_usage_error() {
    let (repo, _remote) = decorated();
    let out = repo.run(&["log", "--decorate", "--format=json"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
}
