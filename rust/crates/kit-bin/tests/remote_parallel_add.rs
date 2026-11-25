//! `kit remote add` run by several processes at once keeps every remote.
//!
//! Each command reads the repo config, adds its remote and writes the file
//! back. The config lock makes the three steps one critical section.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::Path;
use std::process::{Command, Output};

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn kit")
}

#[test]
fn parallel_remote_adds_keep_every_remote() {
    const COUNT: usize = 24;
    let (repo, xdg) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    assert!(
        run_in(repo.path(), xdg.path(), &["init", "-q"])
            .status
            .success()
    );

    std::thread::scope(|scope| {
        for n in 0..COUNT {
            let (repo, xdg) = (repo.path(), xdg.path());
            scope.spawn(move || {
                let name = format!("r{n}");
                let url = format!("kit+file:///nowhere/{n}");
                let out = run_in(repo, xdg, &["remote", "add", &name, &url]);
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            });
        }
    });

    let listed = run_in(repo.path(), xdg.path(), &["remote"]);
    let names = String::from_utf8(listed.stdout).unwrap();
    for n in 0..COUNT {
        assert!(
            names.lines().any(|line| line == format!("r{n}")),
            "remote r{n} was lost:\n{names}"
        );
    }
}
