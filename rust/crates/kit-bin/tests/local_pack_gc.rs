//! The collector reports packed payload bytes in its dry run.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::refs;
use kit_core::serialize::serialize;
use kit_core::store::{LocalPackWriter, ObjectStore};

#[test]
fn a_dry_run_reports_packed_payload_bytes_and_keeps_the_files() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    store.try_activate_local_packs().unwrap();
    let guard = store.prune_guard().unwrap();
    let blob = |data: &[u8]| {
        serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap()
    };
    let live = blob(b"retained");
    let mixed_dead = blob(b"mixed garbage");
    let dead = blob(b"whole garbage");
    let mut mixed = LocalPackWriter::new(&store, &guard).unwrap();
    let head = mixed.write(&live).unwrap();
    mixed.write(&mixed_dead).unwrap();
    mixed.publish().unwrap();
    let mut old = LocalPackWriter::new(&store, &guard).unwrap();
    old.write(&dead).unwrap();
    old.publish().unwrap();
    drop(guard);
    refs::write_ref(&layout, "retained", &head).unwrap();
    let pack_dir = layout.objects_dir().join("pack");
    for entry in fs::read_dir(&pack_dir).unwrap() {
        fs::File::open(entry.unwrap().path())
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
    }

    let output = Command::new(env!("CARGO_BIN_EXE_kit"))
        .current_dir(dir.path())
        .args(["gc", "-n"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("would retire 1 wholly dead local pack"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "{} wholly dead bytes, {} mixed dead bytes, {} grace-eligible dead bytes, {} predicted survivor bytes",
            dead.len(),
            mixed_dead.len(),
            dead.len() + mixed_dead.len(),
            live.len(),
        )),
        "{stderr}"
    );
    assert_eq!(fs::read_dir(&pack_dir).unwrap().count(), 4);
}
