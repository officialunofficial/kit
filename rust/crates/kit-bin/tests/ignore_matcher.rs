//! End-to-end coverage for the path-aware `.gitignore`/`.kitignore` matcher.
//! The unit-level grammar is exercised in `kit_core::ignore`; these
//! tests prove the upgraded semantics actually flow through the real
//! commands that consume the matcher — `add` (worktree tree-builder) and
//! `ls-files --others`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Output;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(kit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn kit")
}

fn out_str(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// Fresh repo with a signing key (commits are always signed).
fn repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["init"]).status.success());
    assert!(run_in(root, x, &["keygen"]).status.success());
    (td, xdg)
}

#[test]
fn anchored_pattern_ignores_root_only_through_add() {
    // A leading-slash pattern is anchored to the repo root: it must ignore
    // `secret.txt` at the top level but NOT `sub/secret.txt`.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".kitignore"), "/secret.txt\n").unwrap();
    fs::write(root.join("secret.txt"), b"top\n").unwrap();
    fs::create_dir(root.join("sub")).unwrap();
    fs::write(root.join("sub/secret.txt"), b"nested\n").unwrap();

    assert!(run_in(root, x, &["add", "."]).status.success());
    let tracked = out_str(&run_in(root, x, &["ls-files"]));
    assert!(
        !tracked.contains("\nsecret.txt") && !tracked.starts_with("secret.txt"),
        "anchored /secret.txt must not be staged at root: {tracked:?}"
    );
    assert!(
        tracked.contains("sub/secret.txt"),
        "the nested secret.txt is not anchored and must be staged: {tracked:?}"
    );
}

#[test]
fn double_star_dir_pattern_ignores_at_any_depth() {
    // `**/build/` ignores a `build` directory at any depth — verify the
    // contents never get staged.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".kitignore"), "**/build/\n").unwrap();
    fs::create_dir_all(root.join("a/build")).unwrap();
    fs::write(root.join("a/build/out.o"), b"x\n").unwrap();
    fs::write(root.join("a/keep.txt"), b"k\n").unwrap();

    assert!(run_in(root, x, &["add", "."]).status.success());
    let tracked = out_str(&run_in(root, x, &["ls-files"]));
    assert!(
        tracked.contains("a/keep.txt"),
        "kept file staged: {tracked:?}"
    );
    assert!(
        !tracked.contains("build"),
        "nothing under a/build should be staged: {tracked:?}"
    );
}

#[test]
fn gitignore_is_read_too() {
    // With no `.kitignore`, a `.gitignore` must still be honored by `add`.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".gitignore"), "*.log\n").unwrap();
    fs::write(root.join("debug.log"), b"x\n").unwrap();
    fs::write(root.join("app.txt"), b"y\n").unwrap();

    assert!(run_in(root, x, &["add", "."]).status.success());
    let tracked = out_str(&run_in(root, x, &["ls-files"]));
    assert!(tracked.contains("app.txt"), "app.txt staged: {tracked:?}");
    assert!(
        !tracked.contains("debug.log"),
        ".gitignore *.log must be honored: {tracked:?}"
    );
}

#[test]
fn kitignore_reinclude_overrides_gitignore() {
    // `.kitignore` is applied last, so its re-include (`!`) wins over a
    // `.gitignore` exclusion under last-match-wins.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".gitignore"), "*.log\n").unwrap();
    fs::write(root.join(".kitignore"), "!keep.log\n").unwrap();
    fs::write(root.join("keep.log"), b"k\n").unwrap();
    fs::write(root.join("drop.log"), b"d\n").unwrap();

    assert!(run_in(root, x, &["add", "."]).status.success());
    let tracked = out_str(&run_in(root, x, &["ls-files"]));
    assert!(
        tracked.contains("keep.log"),
        "re-included keep.log must be staged: {tracked:?}"
    );
    assert!(
        !tracked.contains("drop.log"),
        "drop.log stays ignored: {tracked:?}"
    );
}

#[test]
fn ls_files_others_excludes_files_under_ignored_dir() {
    // A file under an ignored directory must be treated as ignored by
    // `ls-files --others --exclude-standard` (ancestor-dir exclusion), even
    // though the file's own name matches no pattern.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".kitignore"), "node_modules/\n").unwrap();
    fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    fs::write(root.join("node_modules/pkg/index.js"), b"x\n").unwrap();
    fs::write(root.join("main.rs"), b"y\n").unwrap();

    // Without --exclude-standard, everything untracked is listed.
    let all = out_str(&run_in(root, x, &["ls-files", "--others"]));
    assert!(
        all.contains("node_modules/pkg/index.js"),
        "all others: {all:?}"
    );
    // With --exclude-standard, the whole ignored subtree is dropped.
    let excl = out_str(&run_in(
        root,
        x,
        &["ls-files", "--others", "--exclude-standard"],
    ));
    assert!(excl.contains("main.rs"), "main.rs kept: {excl:?}");
    assert!(
        !excl.contains("node_modules"),
        "ignored subtree dropped: {excl:?}"
    );
    // And --ignored shows exactly that subtree.
    let ign = out_str(&run_in(root, x, &["ls-files", "--others", "--ignored"]));
    assert!(
        ign.contains("node_modules/pkg/index.js") && !ign.contains("main.rs"),
        "--ignored lists only the ignored subtree: {ign:?}"
    );
}

#[test]
fn clean_fd_keeps_files_under_ignored_dir_without_x() {
    // `clean -fd` (no -x) must NOT delete files under an ignored directory —
    // the whole ignored subtree is kept, while an unrelated untracked dir is
    // removed. Guards against the ancestor-ignore propagation gap.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".kitignore"), "node_modules/\n").unwrap();
    fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    fs::write(root.join("node_modules/pkg/index.js"), b"x\n").unwrap();
    fs::create_dir(root.join("junk")).unwrap();
    fs::write(root.join("junk/tmp.txt"), b"t\n").unwrap();

    assert!(run_in(root, x, &["clean", "-fd"]).status.success());
    assert!(
        root.join("node_modules/pkg/index.js").exists(),
        "files under an ignored dir must survive clean -fd"
    );
    assert!(
        !root.join("junk").exists(),
        "an unrelated untracked dir is removed by clean -fd"
    );
}

#[test]
fn clean_fdx_removes_ignored_dir() {
    // `clean -fdX` removes ONLY ignored content — the ignored directory and
    // everything under it, even though the children match no pattern.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".kitignore"), "node_modules/\n").unwrap();
    fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    fs::write(root.join("node_modules/pkg/index.js"), b"x\n").unwrap();
    fs::write(root.join("keep.txt"), b"k\n").unwrap();

    assert!(run_in(root, x, &["clean", "-fdX"]).status.success());
    assert!(
        !root.join("node_modules").exists(),
        "clean -fdX removes the ignored directory and its contents"
    );
    assert!(
        root.join("keep.txt").exists(),
        "clean -X keeps non-ignored untracked files"
    );
}

#[test]
fn tracked_file_matching_gitignore_stays_visible_and_restages() {
    // A file that is tracked BEFORE a matching ignore rule appears must keep
    // behaving like a tracked file: it stays in the worktree snapshot (not
    // misreported as deleted) and `add .` still restages its modifications.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("debug.log"), b"v1\n").unwrap();
    assert!(run_in(root, x, &["add", "debug.log"]).status.success());
    assert!(
        run_in(root, x, &["commit", "-m", "track log"])
            .status
            .success()
    );

    // Now an ignore rule appears, and the tracked file is modified.
    fs::write(root.join(".gitignore"), "*.log\n").unwrap();
    fs::write(root.join("debug.log"), b"v2\n").unwrap();

    // It must NOT be reported as a deletion, and stays tracked.
    let status = out_str(&run_in(root, x, &["status", "--porcelain"]));
    assert!(
        !status
            .lines()
            .any(|l| l.contains("debug.log") && l.trim_start().starts_with('D')),
        "tracked file matching .gitignore must not show as deleted: {status:?}"
    );
    assert!(
        out_str(&run_in(root, x, &["ls-files"])).contains("debug.log"),
        "the tracked file stays tracked despite the ignore rule"
    );

    // `add .` restages the tracked file's modification.
    assert!(run_in(root, x, &["add", "."]).status.success());
    let staged = out_str(&run_in(root, x, &["status", "--porcelain"]));
    assert!(
        staged
            .lines()
            .any(|l| l.contains("debug.log") && l.starts_with('M')),
        "add . must restage the tracked-but-ignored modification: {staged:?}"
    );
}

#[test]
fn tracked_ignored_file_not_deleted_in_status_without_index_file() {
    // The seed-from-HEAD path: with NO on-disk index (as right after a
    // checkout), a tracked file matching .gitignore must still be recognized
    // as tracked, not reported as a deletion.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("debug.log"), b"v1\n").unwrap();
    assert!(run_in(root, x, &["add", "debug.log"]).status.success());
    assert!(
        run_in(root, x, &["commit", "-m", "track log"])
            .status
            .success()
    );
    fs::write(root.join(".gitignore"), "*.log\n").unwrap();
    // Simulate a fresh checkout: remove the staging index file entirely.
    let _ = fs::remove_file(root.join(".kit").join("index"));

    let status = out_str(&run_in(root, x, &["status", "--porcelain"]));
    assert!(
        !status
            .lines()
            .any(|l| l.contains("debug.log") && l.trim_start().starts_with('D')),
        "tracked file matching .gitignore must not show as deleted without an index file: {status:?}"
    );
}

#[test]
fn clean_fd_keeps_untracked_sibling_in_ignored_dir_with_tracked_content() {
    // An ignored directory that ALSO holds tracked content must still shield
    // its untracked siblings from `clean -fd` (without -x). Guards the
    // tracked-descend branch's ancestor-ignore propagation.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
    fs::create_dir(root.join("node_modules")).unwrap();
    fs::write(root.join("node_modules/tracked.js"), b"t\n").unwrap();
    // Track a file inside the ignored dir (force past the ignore rule).
    assert!(
        run_in(root, x, &["add", "-f", "node_modules/tracked.js"])
            .status
            .success()
    );
    assert!(
        run_in(root, x, &["commit", "-m", "track one"])
            .status
            .success()
    );
    // An untracked sibling under the same ignored dir.
    fs::write(root.join("node_modules/local.tmp"), b"l\n").unwrap();

    assert!(run_in(root, x, &["clean", "-fd"]).status.success());
    assert!(
        root.join("node_modules/local.tmp").exists(),
        "untracked sibling under an ignored dir must survive clean -fd"
    );
    assert!(
        root.join("node_modules/tracked.js").exists(),
        "tracked file is never cleaned"
    );
}

#[test]
fn add_explicit_ignored_path_refused_without_force() {
    // git refuses an explicitly-named ignored path unless `-f`.
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".kitignore"), "*.secret\n").unwrap();
    fs::write(root.join("app.secret"), b"s\n").unwrap();
    fs::write(root.join("app.txt"), b"t\n").unwrap();

    // Plain add of the ignored path errors and stages nothing.
    let refused = run_in(root, x, &["add", "app.secret"]);
    assert!(
        !refused.status.success(),
        "ignored add must error: {refused:?}"
    );
    assert!(
        !out_str(&run_in(root, x, &["ls-files"])).contains("app.secret"),
        "the ignored path must not have been staged"
    );
    // A non-ignored explicit path still works.
    assert!(run_in(root, x, &["add", "app.txt"]).status.success());
    // `-f` overrides and stages the ignored path.
    assert!(
        run_in(root, x, &["add", "-f", "app.secret"])
            .status
            .success()
    );
    assert!(
        out_str(&run_in(root, x, &["ls-files"])).contains("app.secret"),
        "-f must stage the ignored path"
    );
}

#[test]
fn nested_ignore_rules_match_git_and_clean_preserves_reincluded_files() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(
        std::process::Command::new("git")
            .arg("init")
            .arg(root)
            .output()
            .unwrap()
            .status
            .success()
    );
    fs::create_dir_all(x.join("git")).unwrap();
    fs::write(x.join("git/ignore"), "*.global\n*.log\n").unwrap();
    fs::create_dir_all(root.join(".kit/info")).unwrap();
    fs::write(root.join(".kit/info/exclude"), "!info.global\n").unwrap();
    fs::write(root.join(".git/info/exclude"), "!info.global\n").unwrap();
    fs::write(root.join(".gitignore"), "blocked/\n*.tmp\n!root.global\n").unwrap();
    fs::create_dir_all(root.join("sub/deep")).unwrap();
    fs::create_dir_all(root.join("blocked")).unwrap();
    fs::write(
        root.join("sub/.gitignore"),
        "!keep.tmp\n/local\n!keep.log\n",
    )
    .unwrap();
    fs::write(root.join("sub/deep/.gitignore"), "keep.tmp\n").unwrap();
    fs::write(root.join("blocked/.gitignore"), "!keep.tmp\n").unwrap();
    let cases = [
        ("a.global", true),
        ("root.global", false),
        ("info.global", false),
        ("a.tmp", true),
        ("sub/keep.tmp", false),
        ("sub/drop.tmp", true),
        ("sub/local", true),
        ("sub/deep/local", false),
        ("sub/deep/keep.tmp", true),
        ("blocked/keep.tmp", true),
        ("sub/keep.log", false),
    ];
    for (path, ignored) in cases {
        fs::write(root.join(path), "data").unwrap();
        let git = std::process::Command::new("git")
            .args(["check-ignore", "-v", "--no-index", path])
            .current_dir(root)
            .env("XDG_CONFIG_HOME", x)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        let detail = String::from_utf8_lossy(&git.stdout);
        let git_ignored = git.status.success()
            && !detail
                .split('\t')
                .next()
                .unwrap_or("")
                .rsplit(':')
                .next()
                .unwrap_or("")
                .starts_with('!');
        assert_eq!(git_ignored, ignored, "git {path}: {detail}");
    }
    let others = out_str(&run_in(
        root,
        x,
        &["ls-files", "--others", "--exclude-standard"],
    ));
    let status = out_str(&run_in(
        root,
        x,
        &["status", "--porcelain"],
    ));
    for (path, ignored) in cases {
        assert_eq!(
            others.lines().any(|line| line == path),
            !ignored,
            "ls-files {path}"
        );
        assert_eq!(
            status.lines().any(|line| line.ends_with(path)),
            !ignored,
            "status {path}: {status}"
        );
    }
    assert!(run_in(root, x, &["clean", "-fdX"]).status.success());
    for (path, ignored) in cases {
        assert_eq!(root.join(path).exists(), !ignored, "clean -X {path}");
    }
    assert!(run_in(root, x, &["add", "sub/keep.tmp"]).status.success());
    assert!(!run_in(root, x, &["add", "sub/local"]).status.success());
    assert!(run_in(root, x, &["add", "."]).status.success());
    let tracked = out_str(&run_in(root, x, &["ls-files"]));
    assert!(tracked.lines().any(|line| line == "sub/keep.log"));
}

#[test]
fn nested_kitignore_wins_and_excluded_parent_rules_are_not_read() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join(".gitignore"), "*.tmp\nblocked/\n").unwrap();
    fs::write(root.join("sub/.gitignore"), "*.log\n").unwrap();
    fs::write(root.join("sub/.kitignore"), "!keep.log\n!keep.tmp\n").unwrap();
    fs::write(root.join("sub/keep.log"), "keep").unwrap();
    fs::write(root.join("sub/keep.tmp"), "keep").unwrap();
    fs::create_dir(root.join("blocked")).unwrap();
    fs::write(root.join("blocked/.gitignore"), vec![b'a'; 1024 * 1024 + 1]).unwrap();
    fs::write(root.join("blocked/keep.tmp"), "keep").unwrap();
    assert!(run_in(root, x, &["add", "."]).status.success());
    let tracked = out_str(&run_in(root, x, &["ls-files"]));
    assert!(tracked.contains("sub/keep.tmp"));
    assert!(tracked.contains("sub/keep.log"));
    assert!(!tracked.contains("blocked/"));
    assert!(
        !run_in(root, x, &["add", "blocked/keep.tmp"])
            .status
            .success()
    );
    // -x intentionally removes every untracked file, including re-inclusions.
    fs::write(root.join("sub/new.log"), "remove").unwrap();
    assert!(run_in(root, x, &["clean", "-fdx"]).status.success());
    assert!(!root.join("sub/new.log").exists());
    assert!(root.join("sub/keep.log").exists());
}
