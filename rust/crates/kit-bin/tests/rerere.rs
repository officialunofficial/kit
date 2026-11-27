//! Recorded conflict resolutions (`rerere`): with `rerere.enabled`, a
//! resolved text conflict is recorded when the operation continues, and the
//! same conflict later gets the recorded resolution written into the file,
//! unstaged unless `rerere.autoUpdate`. `kit rerere` lists, shows, forgets,
//! clears and expires entries.

#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::path::PathBuf;
use std::process::Output;

use common::Repo;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn rev(repo: &Repo, spec: &str) -> String {
    stdout(&repo.ok(&["rev-parse", spec])).trim().to_owned()
}

fn read(repo: &Repo, path: &str) -> String {
    std::fs::read_to_string(repo.path().join(path)).unwrap()
}

fn in_progress(repo: &Repo) -> bool {
    common::in_progress(&repo.kit_dir()).is_some()
}

fn cache(repo: &Repo) -> PathBuf {
    repo.kit_dir().join("rr-cache")
}

/// The entry directories of the cache.
fn entries(repo: &Repo) -> Vec<PathBuf> {
    let Ok(dir) = std::fs::read_dir(cache(repo)) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = dir
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    out
}

/// `main` is `base` then `M`, which sets `f.txt` to `main`. `topic`, made
/// from `base`, sets it to `topic` in `T` and adds `g.txt` in `G`, which
/// sets `g.txt` on `main` too in `M2`. `HEAD` is `topic`, and rerere is on.
fn setup() -> Repo {
    let repo = Repo::new();
    repo.ok(&["config", "rerere.enabled", "true"]);
    repo.commit_file("f.txt", b"base\n", "base");
    repo.commit_file("g.txt", b"base g\n", "base g");
    repo.ok(&["branch", "topic"]);
    repo.commit_file("f.txt", b"main\n", "M");
    repo.commit_file("g.txt", b"main g\n", "M2");
    repo.ok(&["switch", "topic"]);
    repo.commit_file("f.txt", b"topic\n", "T");
    repo.commit_file("g.txt", b"topic g\n", "G");
    repo
}

/// Rebase `topic` onto `main`, resolve `f.txt` to `resolved`, and continue
/// into the conflict on `g.txt`.
fn resolve_first(repo: &Repo) {
    let out = repo.run(&["rebase", "main"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    std::fs::write(repo.path().join("f.txt"), b"resolved\n").unwrap();
    repo.ok(&["add", "f.txt"]);
    let out = repo.run(&["rebase", "--continue"]);
    assert!(
        stderr(&out).contains("Recorded resolution for 'f.txt'."),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_resolution_is_replayed_after_an_abort_and_a_second_rebase() {
    let repo = setup();
    resolve_first(&repo);
    assert!(in_progress(&repo), "the second commit conflicts");
    repo.ok(&["rebase", "--abort"]);

    let out = repo.run(&["rebase", "main"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Resolved 'f.txt' using previous resolution."),
        "{}",
        stderr(&out)
    );
    assert_eq!(read(&repo, "f.txt"), "resolved\n");
}

#[test]
fn a_replayed_resolution_is_not_staged_without_auto_update() {
    let repo = setup();
    resolve_first(&repo);
    repo.ok(&["rebase", "--abort"]);
    repo.run(&["rebase", "main"]);
    assert_eq!(read(&repo, "f.txt"), "resolved\n");
    // The index keeps the conflict, so the rebase does not go on.
    let out = repo.run(&["rebase", "--continue"]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(in_progress(&repo));
    repo.ok(&["add", "f.txt"]);
    let out = repo.run(&["rebase", "--continue"]);
    assert!(stderr(&out).contains("g.txt"), "{}", stderr(&out));
}

#[test]
fn auto_update_stages_the_replayed_resolution() {
    let repo = setup();
    repo.ok(&["config", "rerere.autoupdate", "true"]);
    resolve_first(&repo);
    repo.ok(&["rebase", "--abort"]);
    repo.run(&["rebase", "main"]);
    // `f.txt` is staged already, so the continue reaches `g.txt`.
    let out = repo.run(&["rebase", "--continue"]);
    assert!(
        stderr(&out).contains("CONFLICT (content): Merge conflict in g.txt"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn rerere_is_off_by_default() {
    let repo = setup();
    repo.ok(&["config", "rerere.enabled", "false"]);
    resolve_first_without_record(&repo);
    repo.ok(&["rebase", "--abort"]);
    let out = repo.run(&["rebase", "main"]);
    assert!(!stderr(&out).contains("previous resolution"), "{}", stderr(&out));
    assert!(read(&repo, "f.txt").contains("<<<<<<< ours"));
    assert!(entries(&repo).is_empty());
}

fn resolve_first_without_record(repo: &Repo) {
    repo.run(&["rebase", "main"]);
    std::fs::write(repo.path().join("f.txt"), b"resolved\n").unwrap();
    repo.ok(&["add", "f.txt"]);
    let out = repo.run(&["rebase", "--continue"]);
    assert!(!stderr(&out).contains("Recorded"), "{}", stderr(&out));
}

#[test]
fn a_conflict_with_its_sides_swapped_matches_the_same_entry() {
    let repo = Repo::new();
    repo.ok(&["config", "rerere.enabled", "true"]);
    let feature = common::diverge_on(&repo, "a.txt");
    let main = rev(&repo, "main");
    let feature_tip = rev(&repo, feature);
    // Merge `feature` into `main`: ours is `main`.
    let out = repo.run(&["merge", feature]);
    assert!(!out.status.success(), "{}", stderr(&out));
    std::fs::write(repo.path().join("a.txt"), b"both\n").unwrap();
    repo.ok(&["add", "a.txt"]);
    let out = repo.run(&["commit", "-m", "merge feature"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Recorded resolution for 'a.txt'."),
        "{}",
        stderr(&out)
    );
    assert_eq!(entries(&repo).len(), 1);

    // Merge `main` (before the merge) into `feature`: the sides swap.
    repo.ok(&["switch", feature]);
    assert_eq!(rev(&repo, "HEAD"), feature_tip);
    let out = repo.run(&["merge", &main]);
    assert!(!out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("Resolved 'a.txt' using previous resolution."),
        "{}",
        stderr(&out)
    );
    assert_eq!(read(&repo, "a.txt"), "both\n");
    assert_eq!(entries(&repo).len(), 1);
}

#[test]
fn cherry_pick_records_and_replays() {
    let repo = Repo::new();
    repo.ok(&["config", "rerere.enabled", "true"]);
    let feature = common::diverge_on(&repo, "a.txt");
    let main = rev(&repo, "main");
    repo.run(&["cherry-pick", feature]);
    std::fs::write(repo.path().join("a.txt"), b"picked\n").unwrap();
    repo.ok(&["add", "a.txt"]);
    let out = repo.run(&["cherry-pick", "--continue"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("Recorded resolution"), "{}", stderr(&out));

    repo.ok(&["reset", "--hard", &main]);
    let out = repo.run(&["cherry-pick", feature]);
    assert!(
        stderr(&out).contains("Resolved 'a.txt' using previous resolution."),
        "{}",
        stderr(&out)
    );
    assert_eq!(read(&repo, "a.txt"), "picked\n");
}

#[test]
fn status_and_diff_show_the_tracked_conflicts() {
    let repo = setup();
    repo.run(&["rebase", "main"]);
    let status = stdout(&repo.ok(&["rerere", "status"]));
    assert_eq!(status, "f.txt\n");
    std::fs::write(repo.path().join("f.txt"), b"resolved\n").unwrap();
    let diff = stdout(&repo.ok(&["rerere", "diff"]));
    assert!(diff.contains("-<<<<<<<"), "{diff}");
    assert!(diff.contains("+resolved"), "{diff}");
}

#[test]
fn forget_drops_the_recorded_resolution() {
    let repo = setup();
    resolve_first(&repo);
    repo.ok(&["rebase", "--abort"]);
    repo.run(&["rebase", "main"]);
    assert_eq!(read(&repo, "f.txt"), "resolved\n");
    repo.ok(&["rerere", "forget", "f.txt"]);
    let entry = &entries(&repo)[0];
    assert!(!entry.join("postimage").exists());
    repo.ok(&["rebase", "--abort"]);
    let out = repo.run(&["rebase", "main"]);
    assert!(!stderr(&out).contains("previous resolution"), "{}", stderr(&out));
    assert!(read(&repo, "f.txt").contains("<<<<<<< ours"));

    let out = repo.run(&["rerere", "forget", "no-such.txt"]);
    assert!(!out.status.success(), "{}", stderr(&out));
}

#[test]
fn clear_empties_the_cache() {
    let repo = setup();
    resolve_first(&repo);
    assert!(!entries(&repo).is_empty());
    repo.ok(&["rerere", "clear"]);
    assert!(entries(&repo).is_empty());
}

#[test]
fn gc_drops_entries_older_than_the_configured_age() {
    let repo = setup();
    // `f.txt` gets a resolution; `g.txt` stays unresolved.
    resolve_first(&repo);
    assert_eq!(entries(&repo).len(), 2);
    repo.ok(&["rerere", "gc"]);
    assert_eq!(entries(&repo).len(), 2, "the defaults keep fresh entries");

    repo.ok(&["config", "gc.rerereresolved", "0"]);
    repo.ok(&["rerere", "gc"]);
    let left = entries(&repo);
    assert_eq!(left.len(), 1);
    assert!(!left[0].join("postimage").exists());

    repo.ok(&["config", "gc.rerereunresolved", "0"]);
    repo.ok(&["rerere", "gc"]);
    assert!(entries(&repo).is_empty());
}

#[test]
fn a_malformed_entry_is_ignored_with_a_warning() {
    let repo = setup();
    resolve_first(&repo);
    repo.ok(&["rebase", "--abort"]);
    // Change a side, so the entry no longer matches its id.
    for entry in entries(&repo) {
        if entry.join("postimage").exists() {
            std::fs::write(entry.join("side1"), b"tampered\n").unwrap();
        }
    }
    let out = repo.run(&["rebase", "main"]);
    assert!(stderr(&out).contains("warning"), "{}", stderr(&out));
    assert!(!stderr(&out).contains("previous resolution"), "{}", stderr(&out));
    assert!(read(&repo, "f.txt").contains("<<<<<<< ours"));
}

#[test]
fn an_unknown_cache_version_is_ignored_with_a_warning() {
    let repo = setup();
    resolve_first(&repo);
    repo.ok(&["rebase", "--abort"]);
    std::fs::write(cache(&repo).join("version"), b"kit-rerere 9\n").unwrap();
    let out = repo.run(&["rebase", "main"]);
    assert!(stderr(&out).contains("warning"), "{}", stderr(&out));
    assert!(read(&repo, "f.txt").contains("<<<<<<< ours"));
}

#[test]
fn rerere_rejects_an_unknown_subcommand() {
    let repo = setup();
    let out = repo.run(&["rerere", "remaining"]);
    assert_eq!(out.status.code(), Some(64), "{}", stderr(&out));
}
