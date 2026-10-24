//! The deprecated `mkit` binary prints a notice and runs `kit`.

use std::process::Command;

fn shim() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mkit"))
}

#[test]
fn prints_notice_and_forwards_stdout() {
    let out = shim().arg("--version").output().unwrap();
    let kit = Command::new(env!("CARGO_BIN_EXE_kit"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, kit.stdout);
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.starts_with("warning: `mkit` is deprecated. Use `kit` instead."),
        "{err}"
    );
}

#[test]
fn forwards_exit_code() {
    let out = shim().arg("no-such-subcommand").output().unwrap();
    let kit = Command::new(env!("CARGO_BIN_EXE_kit"))
        .arg("no-such-subcommand")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(out.status.code(), kit.status.code());
}
