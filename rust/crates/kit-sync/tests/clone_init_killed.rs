//! A clone into a directory where an earlier `init` was killed before it wrote
//! the format marker starts over, as `kit init` does.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use kit_sync::CloneRemote;

fn remote() -> CloneRemote {
    CloneRemote {
        name: "origin".into(),
        url: "kit+memory://killed-init".into(),
        kind: "memory".into(),
    }
}

#[test]
fn a_clone_dir_without_a_format_marker_or_objects_is_new() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".kit/objects")).unwrap();
    let layout = kit_sync::init_clone_dir(dir.path(), &remote()).unwrap();
    assert!(layout.format_file().is_file());
    assert!(layout.head_file().is_file());
    assert!(layout.config_file().is_file());
}

#[test]
fn a_clone_dir_with_objects_but_no_format_marker_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".kit/objects/ab")).unwrap();
    assert!(kit_sync::init_clone_dir(dir.path(), &remote()).is_err());
}
