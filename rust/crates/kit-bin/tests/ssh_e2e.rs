//! End-to-end coverage for the `kit+ssh://` transport and the trust-pinning
//! wiring.
//!
//! ## What this proves
//!
//! 1. A full `kit clone kit+ssh://…` moves real data through the SSH
//!    transport: the `Hello` handshake, ref negotiation, and upload-pack
//!    all run against a real `kit serve` on the far side. The cloned
//!    repo's HEAD ref and object content MATCH the source.
//!
//! 2. The per-repo `ssh.*` trust-pinning config keys
//!    (`ssh.strict_host_key_checking`, `ssh.user_known_hosts_file`,
//!    `ssh.identity_file`) actually reach the spawned `ssh` program as
//!    `-o StrictHostKeyChecking=…`, `-o UserKnownHostsFile=…`, and
//!    `-i …`. If the keys stopped reaching `SshOptions`, the recorded argv
//!    would lack them and the test would fail.
//!
//! ## How it stays hermetic
//!
//! `build_ssh_command` honours `KIT_SSH_PROGRAM` (the testability seam).
//! We point it at a generated `/bin/sh` wrapper that:
//!
//!   (a) appends its entire argv to `$KIT_SSH_ARGV_LOG`, then
//!   (b) finds the `kit` token in that argv and `exec`s
//!       `$KIT_SSH_TARGET_BIN serve <path>` locally with inherited
//!       stdin/stdout — i.e. it replaces the network hop with a local
//!       `kit serve`, while still exercising the real wire protocol.
//!
//! Both env vars are set on the `kit clone` process and inherited by the
//! spawned wrapper, so the script body stays fully static (no path is
//! interpolated into shell source).
//!
//! No sshd, no network, no `ssh` binary required.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use kit_core::layout::RepoLayout;
use kit_core::ops::reachable_objects;
use kit_core::refs;
use kit_core::store::ObjectStore;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

/// Drive the real `kit` binary, fully isolated from the developer's
/// environment. `extra_env` lets a test add the `KIT_SSH_*` vars.
fn run_in(cwd: &Path, xdg: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(kit_bin());
    cmd.args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .env("HOME", xdg)
        .env("EDITOR", "true")
        .env("VISUAL", "true")
        .stdin(Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("spawn kit")
}

/// Write the hermetic ssh-wrapper script and `chmod +x` it. The script
/// records its argv and execs `$KIT_SSH_TARGET_BIN serve <path>`.
///
/// All dynamic inputs (the argv log path, the target binary) arrive via
/// the environment, so the script body is fully static — no path is
/// interpolated into shell source, leaving no injection surface. The
/// caller sets `KIT_SSH_ARGV_LOG` and `KIT_SSH_TARGET_BIN` on the
/// `kit clone` process; `build_ssh_command` spawns this wrapper without
/// clearing the environment, so both vars reach it.
fn write_ssh_wrapper(dir: &Path) -> std::path::PathBuf {
    let wrapper = dir.join("fake_ssh.sh");
    // `set -eu`: fail loud on any error and on a missing KIT_SSH_* var
    // rather than silently logging to nowhere or exec'ing an empty path.
    let script = r#"#!/bin/sh
set -eu

# Record the full argv this wrapper was invoked with, one token per line,
# framed by a record separator so the test can scan a single invocation.
{
  echo "=== ssh invocation ==="
  for a in "$@"; do
    printf '%s\n' "$a"
  done
} >> "$KIT_SSH_ARGV_LOG"

# Find the `kit serve <path>` triple at the tail of the argv and exec it
# locally. We walk forward to the literal `kit` token; everything after
# `kit serve` is the path.
found=0
path=""
for a in "$@"; do
  if [ "$found" = 2 ]; then
    path="$a"
    break
  fi
  if [ "$found" = 1 ] && [ "$a" = serve ]; then
    found=2
    continue
  fi
  if [ "$a" = kit ]; then
    found=1
  fi
done

if [ -z "$path" ]; then
  echo "fake_ssh: could not locate 'kit serve <path>' in argv" >&2
  exit 64
fi

exec "$KIT_SSH_TARGET_BIN" serve "$path"
"#;
    fs::write(&wrapper, script).expect("write wrapper");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&wrapper).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&wrapper, perms).unwrap();
    }
    wrapper
}

/// Build `root/source` as a repo with real committed content. Returns
/// its path.
fn build_source(root: &Path, xdg: &Path) -> std::path::PathBuf {
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    assert!(
        run_in(&source, xdg, &["init"], &[]).status.success(),
        "init source"
    );
    assert!(
        run_in(&source, xdg, &["keygen"], &[]).status.success(),
        "keygen source"
    );
    fs::write(source.join("README.md"), b"# e2e ssh project\n").unwrap();
    fs::create_dir_all(source.join("src")).unwrap();
    fs::write(
        source.join("src/main.rs"),
        b"fn main() { println!(\"hi\"); }\n",
    )
    .unwrap();
    assert!(
        run_in(&source, xdg, &["add", "."], &[]).status.success(),
        "add source"
    );
    let commit = run_in(&source, xdg, &["commit", "-m", "e2e-1"], &[]);
    assert!(
        commit.status.success(),
        "commit source: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
    source
}

/// Build a source repo with real committed content, then push it to a
/// freshly-initialised `remote` repo so the remote carries the packmap
/// refs that `clone` reconstructs from. Returns the served `remote`
/// repo path.
///
/// kit's transfer dialect is packmap-only: a branch tip is only
/// fetchable once a push has advertised `refs/kit/packmap/<branch>`. A
/// repo that was merely committed-to (never pushed) advertises no
/// packmap, so cloning it yields zero refs. We therefore serve a
/// push-populated remote, exactly as a real deployment would.
fn build_and_push_source(root: &Path, xdg: &Path) -> std::path::PathBuf {
    let source = build_source(root, xdg);

    let remote = root.join("remote");
    fs::create_dir_all(&remote).unwrap();
    assert!(
        run_in(&remote, xdg, &["init"], &[]).status.success(),
        "init remote"
    );
    let remote_url = format!("kit+file://{}", remote.display());
    assert!(
        run_in(&source, xdg, &["remote", "add", "origin", &remote_url], &[])
            .status
            .success(),
        "remote add"
    );
    let push = run_in(&source, xdg, &["push", "origin"], &[]);
    assert!(
        push.status.success(),
        "push source -> remote: {}",
        String::from_utf8_lossy(&push.stderr)
    );
    remote
}

#[test]
fn ssh_clone_moves_data_and_delivers_pinned_options() {
    // Skip cleanly on non-unix where the /bin/sh wrapper can't run.
    if cfg!(not(unix)) {
        eprintln!("ssh_e2e: skipped (requires a POSIX shell)");
        return;
    }

    let work = tempfile::tempdir().expect("work tempdir");
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let root = work.path();

    // --- Source repo with real content, pushed to a served remote -------
    let remote = build_and_push_source(root, xdg.path());
    let source = root.join("source");
    let source_tip = refs::read_ref(&RepoLayout::single(&source), "main")
        .unwrap()
        .expect("source has refs/heads/main");

    // --- Pinned trust options: real files on disk -----------------------
    let known_hosts = root.join("project.known_hosts");
    fs::write(&known_hosts, b"# pinned known hosts for e2e\n").unwrap();
    let identity = root.join("id_ed25519_e2e");
    fs::write(&identity, b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n").unwrap();
    // Must NOT be "accept-new": `build_ssh_command` emits
    // `StrictHostKeyChecking=accept-new` as its default baseline whenever
    // the configured value is empty, so an `accept-new` pin would pass the
    // assertion below even on pre-fix code. "yes" is only ever produced by
    // the live Config→SshOptions wiring, making the assertion discriminating.
    // The hermetic `fake_ssh.sh` shim ignores all `-o` options, so the
    // clone still succeeds regardless of the value.
    let strict_value = "yes";

    // Set the three ssh.* keys in the USER-scoped config (they are
    // REPO_FORBIDDEN_KEYS, so only user scope may set them). `kit
    // config <key> <val>` writes to $XDG_CONFIG_HOME/kit/config.
    for (key, val) in [
        ("ssh.strict_host_key_checking", strict_value),
        ("ssh.user_known_hosts_file", known_hosts.to_str().unwrap()),
        ("ssh.identity_file", identity.to_str().unwrap()),
    ] {
        let out = run_in(root, xdg.path(), &["config", key, val], &[]);
        assert!(
            out.status.success(),
            "set {key}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // --- Hermetic ssh wrapper -------------------------------------------
    let argv_log = root.join("ssh_argv.log");
    let wrapper = write_ssh_wrapper(root);

    // --- Clone over kit+ssh:// -----------------------------------------
    // We serve the push-populated `remote` repo (it carries the packmap
    // refs `clone` reconstructs from). The path must satisfy the strict
    // ssh-path charset (`[A-Za-z0-9._-/]`); tempdir paths qualify.
    let remote_path = remote.to_str().unwrap();
    let url = format!("kit+ssh://e2euser@localhost{remote_path}");
    let dest = root.join("dest");
    let dest_str = dest.to_str().unwrap();

    let clone = run_in(
        root,
        xdg.path(),
        &["clone", &url, dest_str],
        &[
            ("KIT_SSH_PROGRAM", wrapper.to_str().unwrap()),
            ("KIT_SSH_ARGV_LOG", argv_log.to_str().unwrap()),
            ("KIT_SSH_TARGET_BIN", kit_bin()),
        ],
    );
    assert!(
        clone.status.success(),
        "clone over ssh must succeed; stderr:\n{}",
        String::from_utf8_lossy(&clone.stderr)
    );

    // --- (b) HEAD ref + object closure MATCH the source -----------------
    let dest_tip = refs::read_ref(&RepoLayout::single(&dest), "main")
        .unwrap()
        .expect("cloned repo has refs/heads/main");
    assert_eq!(
        source_tip, dest_tip,
        "cloned HEAD must equal source HEAD (real ref negotiation)"
    );

    let source_store = ObjectStore::open(&RepoLayout::single(&source)).unwrap();
    let dest_store = ObjectStore::open(&RepoLayout::single(&dest)).unwrap();
    let source_set: HashSet<_> = reachable_objects(&source_store, &source_tip)
        .unwrap()
        .into_iter()
        .collect();
    let dest_set: HashSet<_> = reachable_objects(&dest_store, &dest_tip)
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(
        source_set, dest_set,
        "object closures must match — proves real data moved through the transport"
    );
    assert!(
        source_set.len() >= 4,
        "closure must include >= commit + tree + 2 blobs"
    );

    // --- (c) The pinned options reached the spawned program -------------
    let log = fs::read_to_string(&argv_log).expect("argv log written by wrapper");
    // argv is logged one token per line; assert the consecutive
    // `-o <val>` / `-i <val>` pairs are present.
    let lines: Vec<&str> = log.lines().collect();
    assert!(
        has_pair(
            &lines,
            "-o",
            &format!("StrictHostKeyChecking={strict_value}")
        ),
        "ssh argv missing StrictHostKeyChecking; log:\n{log}"
    );
    assert!(
        has_pair(
            &lines,
            "-o",
            &format!("UserKnownHostsFile={}", known_hosts.display())
        ),
        "ssh argv missing UserKnownHostsFile; log:\n{log}"
    );
    assert!(
        has_pair(&lines, "-i", &identity.display().to_string()),
        "ssh argv missing identity file; log:\n{log}"
    );
}

/// True when `lines` contains `flag` immediately followed by `value`.
fn has_pair(lines: &[&str], flag: &str, value: &str) -> bool {
    lines.windows(2).any(|w| w[0] == flag && w[1] == value)
}

// ------------------------------------------------------------ root mode
//
// `kit serve --root <dir> [--principal <hex>]` serves the repositories
// under `<dir>` addressed by `<namespace>/<name>`; only the namespace's
// owner may write. The wrapper stands in for sshd's forced command: it
// finds the client's `kit serve <path>` in argv (the same scan as
// `fake_ssh.sh`) and execs `kit serve --root` locally — handing the
// path over argv, or over `SSH_ORIGINAL_COMMAND` the way sshd does when
// `KIT_SSH_SERVE_ENV` is set. The asserted principal arrives via
// `KIT_SSH_PRINCIPAL` (absent → no `--principal`, as a forced command
// that asserts none).

/// A hex string as a `&'static str` for `run_in`'s env table.
fn hex(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

/// `ed25519-<64 hex>` — a self-certifying namespace's canonical form.
fn ns(byte: char) -> String {
    format!("ed25519-{}", hex(byte))
}

/// Write the root-mode ssh wrapper (see the header above).
fn write_root_ssh_wrapper(dir: &Path) -> std::path::PathBuf {
    let wrapper = dir.join("fake_ssh_root.sh");
    let script = r#"#!/bin/sh
set -eu

{ echo "=== ssh invocation ==="; for a in "$@"; do printf '%s\n' "$a"; done; } >> "$KIT_SSH_ARGV_LOG"

found=0
path=""
for a in "$@"; do
  if [ "$found" = 2 ]; then
    path="$a"
    break
  fi
  if [ "$found" = 1 ] && [ "$a" = serve ]; then
    found=2
    continue
  fi
  if [ "$a" = kit ]; then
    found=1
  fi
done

if [ -z "$path" ]; then
  echo "fake_ssh_root: could not locate 'kit serve <path>' in argv" >&2
  exit 64
fi

# `KIT_SSH_SERVE_ENV=1`: hand the path over SSH_ORIGINAL_COMMAND the way
# sshd does, instead of as a positional argument.
serve_env=${KIT_SSH_SERVE_ENV:-}
if [ -n "$serve_env" ]; then
  SSH_ORIGINAL_COMMAND="kit serve $path"
  export SSH_ORIGINAL_COMMAND
  path=""
fi

if [ -n "${KIT_SSH_PRINCIPAL:-}" ]; then
  if [ -n "$path" ]; then
    exec "$KIT_SSH_TARGET_BIN" serve --root "$KIT_SSH_ROOT" --principal "$KIT_SSH_PRINCIPAL" "$path"
  fi
  exec "$KIT_SSH_TARGET_BIN" serve --root "$KIT_SSH_ROOT" --principal "$KIT_SSH_PRINCIPAL"
elif [ -n "$path" ]; then
  exec "$KIT_SSH_TARGET_BIN" serve --root "$KIT_SSH_ROOT" "$path"
else
  exec "$KIT_SSH_TARGET_BIN" serve --root "$KIT_SSH_ROOT"
fi
"#;
    fs::write(&wrapper, script).expect("write root wrapper");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&wrapper).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&wrapper, perms).unwrap();
    }
    wrapper
}

/// A `--root` deployment at `work/serve-root` with each of `rooms`
/// `kit init`ed under `ed25519-<owner>`. Returns the root's path.
fn serve_root_with_rooms(
    work: &Path,
    xdg: &Path,
    owner_ns: &str,
    rooms: &[&str],
) -> std::path::PathBuf {
    let serve_root = work.join("serve-root");
    for room in rooms {
        let dir = serve_root.join(owner_ns).join(room);
        fs::create_dir_all(&dir).unwrap();
        let out = run_in(&dir, xdg, &["init"], &[]);
        assert!(
            out.status.success(),
            "init {room}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    serve_root
}

/// The environment `run_in` needs so the spawned `kit` reaches the
/// root-mode wrapper: `KIT_SSH_PROGRAM` picks the wrapper itself, the
/// rest it inherits. `principal` is the asserted `--principal` key
/// (`None` → the forced command asserts none); `env_path` hands the
/// path via `SSH_ORIGINAL_COMMAND` instead of argv.
fn root_env(
    wrapper: &Path,
    serve_root: &Path,
    principal: Option<&str>,
    env_path: bool,
) -> Vec<(String, String)> {
    let mut env = vec![
        (
            "KIT_SSH_PROGRAM".to_owned(),
            wrapper.to_str().unwrap().to_owned(),
        ),
        (
            "KIT_SSH_ARGV_LOG".to_owned(),
            wrapper
                .parent()
                .unwrap()
                .join("ssh_argv.log")
                .to_str()
                .unwrap()
                .to_owned(),
        ),
        ("KIT_SSH_TARGET_BIN".to_owned(), kit_bin().to_owned()),
        (
            "KIT_SSH_ROOT".to_owned(),
            serve_root.to_str().unwrap().to_owned(),
        ),
    ];
    if let Some(key) = principal {
        env.push(("KIT_SSH_PRINCIPAL".to_owned(), key.to_owned()));
    }
    if env_path {
        env.push(("KIT_SSH_SERVE_ENV".to_owned(), "1".to_owned()));
    }
    env
}

/// `kit remote add origin <url>` on `source`, then `push origin` with
/// `env`; returns the push's output.
fn push_over_ssh(source: &Path, xdg: &Path, url: &str, env: &[(String, String)]) -> Output {
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let add = run_in(source, xdg, &["remote", "add", "origin", url], &env);
    assert!(
        add.status.success(),
        "remote add: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    run_in(source, xdg, &["push", "origin"], &env)
}

/// The owner pushes over `kit+ssh://` — sshd's forced command asserting
/// the principal over `SSH_ORIGINAL_COMMAND` — and a clone of the same
/// `<namespace>/<name>` address reconstructs the repo.
#[test]
fn ssh_root_mode_owner_pushes_and_clones() {
    if cfg!(not(unix)) {
        eprintln!("ssh_root_mode: skipped (requires a POSIX shell)");
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let root = work.path();

    let owner_ns = ns('a');
    let serve_root = serve_root_with_rooms(root, xdg.path(), &owner_ns, &["room-a"]);
    let source = build_source(root, xdg.path());
    let wrapper = write_root_ssh_wrapper(root);
    let env = root_env(&wrapper, &serve_root, Some(&hex('a')), true);
    let url = format!("kit+ssh://e2euser@localhost/{owner_ns}/room-a");

    let push = push_over_ssh(&source, xdg.path(), &url, &env);
    assert!(
        push.status.success(),
        "owner push must succeed; stderr:\n{}",
        String::from_utf8_lossy(&push.stderr)
    );

    let dest = root.join("dest");
    let clone = run_in(
        root,
        xdg.path(),
        &["clone", &url, dest.to_str().unwrap()],
        &env.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
    );
    assert!(
        clone.status.success(),
        "clone over ssh must succeed; stderr:\n{}",
        String::from_utf8_lossy(&clone.stderr)
    );
    let source_tip = refs::read_ref(&RepoLayout::single(&source), "main")
        .unwrap()
        .expect("source has refs/heads/main");
    let dest_tip = refs::read_ref(&RepoLayout::single(&dest), "main")
        .unwrap()
        .expect("cloned repo has refs/heads/main");
    assert_eq!(source_tip, dest_tip, "clone must reconstruct the push");
}

/// A principal that is not the namespace's key is denied: the push fails
/// and the error the client surfaces is the pinned
/// `write not permitted` (B11's `INVALID_REQUEST` frame).
#[test]
fn ssh_root_mode_non_owner_push_is_refused() {
    if cfg!(not(unix)) {
        eprintln!("ssh_root_mode: skipped (requires a POSIX shell)");
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let root = work.path();

    let owner_ns = ns('a');
    let serve_root = serve_root_with_rooms(root, xdg.path(), &owner_ns, &["room-a"]);
    let source = build_source(root, xdg.path());
    let wrapper = write_root_ssh_wrapper(root);
    // 'b' is not 'a': the forced command asserts a non-owner key.
    let env = root_env(&wrapper, &serve_root, Some(&hex('b')), false);
    let url = format!("kit+ssh://e2euser@localhost/{owner_ns}/room-a");

    let push = push_over_ssh(&source, xdg.path(), &url, &env);
    assert!(!push.status.success(), "non-owner push must fail: {push:?}");
    let stderr = String::from_utf8_lossy(&push.stderr);
    assert!(
        stderr.contains("write not permitted"),
        "the pinned refusal reaches the client: {stderr}"
    );
    // The refused push wrote nothing: the repo still advertises no refs.
    let dest = root.join("dest");
    let clone = run_in(
        root,
        xdg.path(),
        &["clone", &url, dest.to_str().unwrap()],
        &env.iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
    );
    assert!(clone.status.success(), "{clone:?}");
    assert!(
        refs::read_ref(&RepoLayout::single(&dest), "main")
            .unwrap()
            .is_none(),
        "a denied push leaves the repo with no refs"
    );
}

/// No `--principal` asserted at all: reads work, every write is denied.
#[test]
fn ssh_root_mode_without_principal_reads_but_cannot_write() {
    if cfg!(not(unix)) {
        eprintln!("ssh_root_mode: skipped (requires a POSIX shell)");
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let root = work.path();

    let owner_ns = ns('a');
    let serve_root = serve_root_with_rooms(root, xdg.path(), &owner_ns, &["room-a"]);
    let source = build_source(root, xdg.path());
    let wrapper = write_root_ssh_wrapper(root);
    let url = format!("kit+ssh://e2euser@localhost/{owner_ns}/room-a");

    // Seed the repo as the owner so the read side has content.
    let owner_env = root_env(&wrapper, &serve_root, Some(&hex('a')), false);
    let push = push_over_ssh(&source, xdg.path(), &url, &owner_env);
    assert!(
        push.status.success(),
        "owner push: {}",
        String::from_utf8_lossy(&push.stderr)
    );

    // The same forced command with no --principal: clone works, push fails.
    let anon_env = root_env(&wrapper, &serve_root, None, false);
    let anon: Vec<(&str, &str)> = anon_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let dest = root.join("dest");
    let clone = run_in(
        root,
        xdg.path(),
        &["clone", &url, dest.to_str().unwrap()],
        &anon,
    );
    assert!(
        clone.status.success(),
        "a keyless principal may read: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    // A fast-forward of the branch the clone fetched, so that the refusal
    // can only come from the missing write permission.
    assert!(run_in(&dest, xdg.path(), &["keygen"], &[]).status.success());
    fs::write(dest.join("f.txt"), b"nope\n").unwrap();
    assert!(
        run_in(&dest, xdg.path(), &["add", "."], &[])
            .status
            .success()
    );
    assert!(
        run_in(&dest, xdg.path(), &["commit", "-m", "x"], &[])
            .status
            .success()
    );
    for args in [
        &["remote", "add", "origin", url.as_str()][..],
        &["fetch", "origin"][..],
    ] {
        let out = run_in(&dest, xdg.path(), args, &anon);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let push = run_in(&dest, xdg.path(), &["push", "origin"], &anon);
    assert!(!push.status.success(), "a keyless push must fail: {push:?}");
    assert!(
        String::from_utf8_lossy(&push.stderr).contains("write not permitted"),
        "{}",
        String::from_utf8_lossy(&push.stderr)
    );
}

/// Two repositories under one root are isolated: pushing to
/// `ed25519-<a>/room-a` leaves `ed25519-<a>/room-b` empty.
#[test]
fn ssh_root_mode_isolates_repositories() {
    if cfg!(not(unix)) {
        eprintln!("ssh_root_mode: skipped (requires a POSIX shell)");
        return;
    }
    let work = tempfile::tempdir().expect("work tempdir");
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let root = work.path();

    let owner_ns = ns('a');
    let serve_root = serve_root_with_rooms(root, xdg.path(), &owner_ns, &["room-a", "room-b"]);
    let source = build_source(root, xdg.path());
    let wrapper = write_root_ssh_wrapper(root);
    let env = root_env(&wrapper, &serve_root, Some(&hex('a')), false);
    let url_a = format!("kit+ssh://e2euser@localhost/{owner_ns}/room-a");
    let url_b = format!("kit+ssh://e2euser@localhost/{owner_ns}/room-b");
    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    let push = push_over_ssh(&source, xdg.path(), &url_a, &env);
    assert!(
        push.status.success(),
        "push to room-a: {}",
        String::from_utf8_lossy(&push.stderr)
    );

    // room-b reconstructs nothing of room-a's push.
    let dest_b = root.join("dest-b");
    let clone = run_in(
        root,
        xdg.path(),
        &["clone", &url_b, dest_b.to_str().unwrap()],
        &env_refs,
    );
    assert!(
        clone.status.success(),
        "clone room-b: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    assert!(
        refs::read_ref(&RepoLayout::single(&dest_b), "main")
            .unwrap()
            .is_none(),
        "room-b must not see room-a's refs/heads/main"
    );
    // And the pack the push stored in room-a is not visible through
    // room-b's repo either: cloning it yields zero refs (the ssh-session
    // tests cover `PackExists`/`DownloadPack` at frame level).
}
