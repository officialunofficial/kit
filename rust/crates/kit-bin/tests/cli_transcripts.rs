//! Exact output and exit codes for deterministic CLI errors.

use assert_cmd::Command;

#[test]
fn add_outside_repo_reports_missing_repository() {
    let dir = tempfile::tempdir().expect("create directory outside a kit repository");

    Command::new(env!("CARGO_BIN_EXE_kit"))
        .current_dir(dir.path())
        .args(["add", "foo.txt"])
        .assert()
        .code(1)
        .stdout("")
        .stderr("error: not a kit repo: path is not a kit repository (missing .kit/objects)\n");
}

#[test]
fn serve_without_path_reports_required_argument() {
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .arg("serve")
        .assert()
        .code(64)
        .stdout("")
        .stderr(concat!(
            "error: the following required arguments were not provided:\n",
            "  <PATH>\n",
            "\n",
            "Usage: kit serve <PATH>\n",
            "\n",
            "For more information, try '--help'.\n",
        ));
}

#[test]
fn unknown_subcommand_reports_usage_error() {
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .arg("definitely-nonsense")
        .assert()
        .code(64)
        .stdout("")
        .stderr(
            "error: unknown command 'definitely-nonsense' (run 'kit --help' for a list of commands)\n",
        );
}
