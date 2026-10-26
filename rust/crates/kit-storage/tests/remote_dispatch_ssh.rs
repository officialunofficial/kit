//! Integration coverage for the `kit+ssh` dispatch branch in
//! [`kit_storage::remote_dispatch::open`].
//!
//! ## Why no live SSH subprocess here
//!
//! `SshTransport::connect_with_options` shells out to `ssh(1)` and
//! performs an `OP_HELLO` handshake against a real peer. Running a live
//! subprocess in CI would require:
//!
//! - A known-good `ssh` binary on `$PATH` (not guaranteed on minimal
//!   runner images).
//! - A real or faked sshd with a known host key and an authorised
//!   key-pair — both outside the scope of a unit test.
//! - Tolerance for flaky network / process-spawn failures on busy
//!   runners.
//!
//! That coverage lives in `tests/e2e-ssh.sh` (integration harness, not
//! wired into `cargo test`). This file narrows scope to the URL-parser
//! contract the CLI dispatch depends on: happy-path acceptance plus
//! every rejection branch the SSH-SECURITY.md §2 parser defends. Each
//! assertion exercises the same entry point the CLI dispatch calls —
//! `parse_kit_ssh_url` — so a regression in URL validation would show
//! up here without needing a running sshd.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use kit_storage::remote_dispatch;
use kit_transport_ssh::{parse_kit_ssh_url, validate_ssh_path};

#[test]
// Spawns a real `ssh(1)` subprocess against 127.0.0.1:22 —
// slow and environment-dependent (needs `ssh` on PATH; behavior differs
// depending on whether anything is listening on 22). Quarantined to the
// serial `--ignored` CI lane (cloudbuild/ci.yaml);
// only needs localhost networking, so it runs fine there.
#[ignore = "real ssh(1) subprocess to 127.0.0.1:22; run via the serial --ignored CI lane"]
fn open_accepts_syntactically_valid_kit_ssh_url() {
    // `open()` itself short-circuits on the `kit+ssh://` prefix and
    // calls `SshTransport::connect_with_options` (default options), which
    // DOES spawn `ssh(1)`. We
    // can't guarantee `ssh` is on `$PATH` in CI, so a successful
    // `open()` here would be a test-flakiness hazard. Instead we
    // assert that open EITHER succeeds (ssh is available and a local
    // sshd is running on 127.0.0.1:22) OR fails with an SSH-init /
    // transport error — never with `UnsupportedScheme` or
    // `MalformedUrl`. The first two are the regressions we care about.
    let r = remote_dispatch::open("kit+ssh://git@127.0.0.1:22/repo");
    match r {
        Ok(_) => {
            // Live sshd answered — fine, and proves the branch is wired.
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("unsupported URL scheme"),
                "kit+ssh:// must NOT dispatch to UnsupportedScheme: {msg}"
            );
            assert!(
                !msg.contains("malformed URL"),
                "kit+ssh:// must NOT dispatch to MalformedUrl: {msg}"
            );
        }
    }
}

// -- URL parser: happy path ----------------------------------------------

#[test]
fn parse_happy_path_full_user_host_port_path() {
    let t = parse_kit_ssh_url("kit+ssh://git@git.example.com:2222/myrepo").unwrap();
    assert_eq!(t.user, "git");
    assert_eq!(t.host, "git.example.com");
    assert_eq!(t.port, Some(2222));
    assert_eq!(t.path, "/myrepo");
}

#[test]
fn parse_happy_path_default_port() {
    // No `:port` → `port = None`, ssh(1) picks 22.
    let t = parse_kit_ssh_url("kit+ssh://alice@host/proj").unwrap();
    assert_eq!(t.user, "alice");
    assert_eq!(t.host, "host");
    assert_eq!(t.port, None);
    assert_eq!(t.path, "/proj");
}

#[test]
fn parse_happy_path_nested_path() {
    let t = parse_kit_ssh_url("kit+ssh://bob@h/a/b/c.repo").unwrap();
    assert_eq!(t.path, "/a/b/c.repo");
}

// -- URL parser: rejections ----------------------------------------------

#[test]
fn reject_missing_kit_prefix() {
    assert!(parse_kit_ssh_url("ssh://git@h/p").is_err());
    assert!(parse_kit_ssh_url("git@h:p").is_err());
}

#[test]
fn reject_empty_body() {
    assert!(parse_kit_ssh_url("kit+ssh://").is_err());
}

#[test]
fn reject_missing_user() {
    assert!(parse_kit_ssh_url("kit+ssh://host/p").is_err());
}

#[test]
fn reject_empty_user() {
    assert!(parse_kit_ssh_url("kit+ssh://@host/p").is_err());
}

#[test]
fn reject_empty_host() {
    assert!(parse_kit_ssh_url("kit+ssh://user@/p").is_err());
}

#[test]
fn reject_empty_port() {
    assert!(parse_kit_ssh_url("kit+ssh://user@host:/p").is_err());
}

#[test]
fn reject_port_out_of_range_in_url_form() {
    // URL-form parser rejects digit-only tokens outside `u16::MAX`.
    assert!(parse_kit_ssh_url("kit+ssh://user@host:999999/p").is_err());
}

#[test]
fn reject_non_numeric_port() {
    // A non-numeric token after the host is not a port, and the SCP form
    // `user@host:path` is not a legal `kit+ssh` URL.
    assert!(parse_kit_ssh_url("kit+ssh://user@host:some-repo/branch").is_err());
}

#[test]
fn reject_missing_path() {
    // `user@host` alone has no repo path.
    assert!(parse_kit_ssh_url("kit+ssh://user@host").is_err());
}

#[test]
fn reject_crlf_injection() {
    // SSH-SECURITY.md §2: NUL and CRLF forbidden anywhere in the URL.
    assert!(parse_kit_ssh_url("kit+ssh://user@host/p\r\nX").is_err());
    assert!(parse_kit_ssh_url("kit+ssh://user@host/p\nX").is_err());
}

#[test]
fn reject_nul_injection() {
    assert!(parse_kit_ssh_url("kit+ssh://user@host/p\0X").is_err());
}

// -- Path validation (separate from URL parse) ---------------------------

#[test]
fn path_validation_allows_alphanum_dash_dot_slash() {
    assert!(validate_ssh_path("/alpha/beta-1.repo").is_ok());
    assert!(validate_ssh_path("foo_bar").is_ok());
}

#[test]
fn path_validation_rejects_dotdot() {
    assert!(validate_ssh_path("/a/../b").is_err());
}

#[test]
fn path_validation_rejects_empty_segments() {
    assert!(validate_ssh_path("/a//b").is_err());
}

#[test]
fn path_validation_rejects_shell_metacharacters() {
    // Per SSH-SECURITY.md §2, metachars cannot appear in the path so
    // they can never land on the remote argv as anything other than
    // the opaque repo identifier. Sample the ones most likely to be
    // used for injection: ; & | ` $ space.
    for meta in [
        "/a;b", "/a&b", "/a|b", "/a`b", "/a$b", "/a b", "/a\"b", "/a'b",
    ] {
        assert!(
            validate_ssh_path(meta).is_err(),
            "expected {meta:?} to be rejected by validate_ssh_path"
        );
    }
}

#[test]
fn path_validation_rejects_bare_slash() {
    assert!(validate_ssh_path("/").is_err());
}

#[test]
fn path_validation_rejects_empty() {
    assert!(validate_ssh_path("").is_err());
}
