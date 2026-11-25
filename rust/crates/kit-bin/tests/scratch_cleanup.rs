//! Scratch cleanup after a test command fails.
#![allow(clippy::unwrap_used)]
use std::process::Command;

#[test]
fn scratch_is_removed_after_a_failed_or_killed_test_command() {
    let parent = tempfile::tempdir().unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts/with-test-tmpdir.sh");
    for (command, status) in [
        ("mkdir \"$TMPDIR/leftover\"; exit 9", 9),
        ("mkdir \"$TMPDIR/leftover\"; kill -KILL $$", 137),
    ] {
        let output = Command::new("bash")
            .arg(&script)
            .args(["bash", "-c", command])
            .env("TMPDIR", parent.path())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(status));
        assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}
