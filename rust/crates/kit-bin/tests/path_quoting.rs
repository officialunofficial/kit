//! A file name with a control character is C-quoted in the human output of
//! `status`, `clean` and the commit summary, as `status -s` and git do, so a
//! name cannot write an escape sequence to the terminal.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Output;

const NAME: &str = "x\u{1b}[2Jy.txt";
const QUOTED: &str = r#""x\033[2Jy.txt""#;

fn kit(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn kit")
}

/// Both streams of `out`, which together hold every line of human output.
fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_quoted(what: &str, out: &Output) {
    let text = text(out);
    assert!(
        !text.contains('\u{1b}'),
        "{what} wrote a raw escape byte: {text:?}"
    );
    assert!(
        text.contains(QUOTED),
        "{what} did not quote the name: {text:?}"
    );
}

#[test]
fn human_output_quotes_a_name_with_a_control_character() {
    let dir = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (dir.path(), xdg.path());
    assert!(kit(root, x, &["init"]).status.success());
    assert!(kit(root, x, &["keygen"]).status.success());
    fs::write(root.join(NAME), b"hello\n").unwrap();

    assert_quoted("status", &kit(root, x, &["status"]));
    assert_quoted("clean -n", &kit(root, x, &["clean", "-n"]));

    assert!(kit(root, x, &["add", "."]).status.success());
    assert_quoted("status staged", &kit(root, x, &["status"]));
    let commit = kit(root, x, &["commit", "-m", "add"]);
    assert!(commit.status.success(), "{}", text(&commit));
    assert_quoted("commit summary", &commit);
}
