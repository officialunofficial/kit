//! A push whose pack cannot be written must not leave a file behind. A push
//! seals each pack in an unnamed spool in `.kit/tmp/` before it uploads it,
//! so a file size limit stops it there: it fails as a local I/O error, and
//! neither the spool directory nor the remote keeps a file.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

/// Larger than the file size limit below.
const BLOB_BYTES: usize = 2 * 1024 * 1024;

/// The file size limit in blocks of the shell's `ulimit -f`. It is 128 KiB
/// for 512-byte blocks and 256 KiB for 1024-byte blocks. Both are under the
/// size of the pack.
const FILE_SIZE_LIMIT_BLOCKS: u32 = 256;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(kit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn kit")
}

/// Run `kit args` with a file size limit. A write past the limit fails with
/// an I/O error instead of killing the process.
fn run_with_file_size_limit(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "trap '' XFSZ; ulimit -f {FILE_SIZE_LIMIT_BLOCKS}; exec \"$0\" \"$@\""
        ))
        .arg(kit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn sh")
}

fn ok(out: &Output) {
    assert!(out.status.success(), "command failed: {out:?}");
}

/// Bytes that do not compress: a xorshift stream from a fixed seed.
fn random_blob() -> Vec<u8> {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut bytes = Vec::with_capacity(BLOB_BYTES);
    while bytes.len() < BLOB_BYTES {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(BLOB_BYTES);
    bytes
}

#[test]
fn push_that_cannot_write_its_pack_leaves_no_temporary_file() {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let bare = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    ok(&run_in(root, x, &["init"]));
    ok(&run_in(root, x, &["keygen"]));
    fs::write(root.join("big.bin"), random_blob()).unwrap();
    ok(&run_in(root, x, &["add", "."]));
    ok(&run_in(root, x, &["commit", "-m", "add a big file"]));
    let url = format!("kit+file://{}", bare.path().display());
    ok(&run_in(root, x, &["remote", "add", "origin", &url]));

    let out = run_with_file_size_limit(root, x, &["push", "origin", "--all"]);

    assert!(!out.status.success(), "the push should fail: {out:?}");
    // The push must fail writing its pack, not earlier: it made the spool
    // directory, and the error is the file size limit's.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("File too large"),
        "the failure should be the pack's write: {stderr}"
    );
    let spools = root.join(".kit").join("tmp");
    assert!(spools.is_dir(), "the push should have made {spools:?}");
    let spooled: Vec<_> = fs::read_dir(&spools).unwrap().collect();
    assert!(spooled.is_empty(), "spool files left: {spooled:?}");
    let packs = bare.path().join("packs");
    let leftovers: Vec<_> = fs::read_dir(&packs)
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "files left on the remote: {leftovers:?}"
    );
}
