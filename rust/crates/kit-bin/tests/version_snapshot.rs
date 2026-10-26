//! Snapshot test for the `kit version` stdout contract.
//!
//! This is the byte-exact contract asserted by Homebrew. Any
//! cosmetic change — extra whitespace, a newline at the wrong place,
//! a prefix like `kit-rs` — breaks downstream packaging and must be
//! treated as a major-version semver break. See `docs/CLI.md`.

use std::process::Command;

/// Resolve the built `kit` binary. Cargo sets `CARGO_BIN_EXE_<name>`
/// for every binary target in the *current* crate, which is exactly
/// `kit-bin` here.
fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

#[test]
fn version_stdout_is_byte_exact() {
    let output = Command::new(kit_bin())
        .arg("version")
        .output()
        .expect("spawn `kit version`");
    assert!(output.status.success(), "`kit version` must exit 0");

    let expected = format!("kit {}\n", env!("CARGO_PKG_VERSION"));
    let actual = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert_eq!(
        actual, expected,
        "`kit version` stdout contract broken — see docs/CLI.md"
    );

    // stderr must be empty — we do not print warnings on the happy
    // path.
    assert!(
        output.stderr.is_empty(),
        "`kit version` must not write to stderr, got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The top-level `--version` / `-V` flags are aliases of the `version`
/// subcommand (git-parity). They are part of the same packaging
/// contract, so pin them to byte-identical stdout and empty stderr.
#[test]
fn version_flags_match_subcommand_byte_for_byte() {
    let canonical = Command::new(kit_bin())
        .arg("version")
        .output()
        .expect("spawn `kit version`");
    assert!(canonical.status.success(), "`kit version` must exit 0");

    for flag in ["--version", "-V"] {
        let out = Command::new(kit_bin())
            .arg(flag)
            .output()
            .unwrap_or_else(|e| panic!("spawn `kit {flag}`: {e}"));
        assert!(out.status.success(), "`kit {flag}` must exit 0");
        assert_eq!(
            out.stdout, canonical.stdout,
            "`kit {flag}` stdout must byte-match `kit version`"
        );
        assert!(
            out.stderr.is_empty(),
            "`kit {flag}` must not write to stderr, got: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
