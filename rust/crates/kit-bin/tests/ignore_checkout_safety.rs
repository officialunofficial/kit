//! A checkout must preserve untracked files protected by the pre-checkout rules.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Output;

fn run(root: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(root)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .unwrap()
}

#[test]
fn checkout_keeps_files_ignored_before_ancestor_rules_change() {
    let repo = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let (root, xdg) = (repo.path(), config.path());
    for args in [&["init"][..], &["keygen"]] {
        assert!(run(root, xdg, args).status.success());
    }
    std::fs::create_dir(root.join("config")).unwrap();
    std::fs::write(root.join(".gitignore"), "").unwrap();
    std::fs::write(root.join("config/tracked"), "target").unwrap();
    assert!(run(root, xdg, &["add", "."]).status.success());
    assert!(run(root, xdg, &["commit", "-m", "target"]).status.success());
    let target = String::from_utf8(run(root, xdg, &["rev-parse", "HEAD"]).stdout).unwrap();
    std::fs::write(root.join(".gitignore"), "*.env\n").unwrap();
    std::fs::write(root.join("config/tracked"), "current").unwrap();
    assert!(run(root, xdg, &["add", "."]).status.success());
    assert!(
        run(root, xdg, &["commit", "-m", "protect local files"])
            .status
            .success()
    );
    std::fs::write(root.join("config/secret.env"), "private data").unwrap();
    let result = run(root, xdg, &["checkout", target.trim()]);
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        std::fs::read_to_string(root.join("config/secret.env")).unwrap(),
        "private data"
    );
}
