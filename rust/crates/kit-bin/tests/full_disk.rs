//! Full-disk failures go through the real add path in their own process.
#![allow(clippy::unwrap_used)]

#[test]
fn add_reports_a_full_object_store_as_an_io_failure() {
    let dir = tempfile::tempdir().unwrap();
    let layout = kit_core::layout::RepoLayout::single(dir.path());
    kit_core::store::ObjectStore::init(&layout).unwrap();
    std::fs::write(dir.path().join("file"), b"content to store").unwrap();
    let before = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let failure = kit_core::fault::fail_writes(kit_core::fault::Site::Store);
    let code = kit_bin::commands::add::run(&["file".to_owned()]);
    drop(failure);
    std::env::set_current_dir(before).unwrap();
    assert_eq!(code, kit_bin::exit::IOERR);
    assert!(!layout.worktree_state_dir().join("index").exists());
}
