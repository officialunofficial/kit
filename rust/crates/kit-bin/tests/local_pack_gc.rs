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
    let loose_id = store.write(&live).unwrap();
    let mixed_dead = blob(b"mixed garbage");
    let dead = blob(b"whole garbage");
    let mut mixed = LocalPackWriter::new(&store, &guard).unwrap();
    let head = mixed.write(&live).unwrap();
    assert_eq!(loose_id, head);
    mixed.write(&mixed_dead).unwrap();
    mixed.publish().unwrap();
    let mut old = LocalPackWriter::new(&store, &guard).unwrap();
    old.write(&dead).unwrap();
    old.publish().unwrap();
    drop(guard);
    refs::write_ref(&layout, "retained", &head).unwrap();
    let object_root = layout.objects_dir();
    let pack_dir = object_root.join("pack");
    let leftover = pack_dir.join(format!(".{}.tmp.pack", "a".repeat(32)));
    fs::write(&leftover, b"partial file").unwrap();
    let hex = kit_core::to_hex(&head);
    let loose = object_root.join(&hex[..2]).join(&hex[2..]);
    fs::File::open(&loose)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();
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
    assert!(
        stderr.contains("would prune 1 local pack leftover"),
        "{stderr}"
    );
    assert!(stderr.contains("would prune 1 loose duplicate"), "{stderr}");
    assert_eq!(fs::read_dir(&pack_dir).unwrap().count(), 5);
    assert!(loose.is_file());
}

#[test]
fn a_damaged_pack_warns_in_dry_run_and_clears_fetch_records_on_collection() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    store.try_activate_local_packs().unwrap();
    let guard = store.prune_guard().unwrap();
    let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
    let bytes = serialize(&Object::Blob(Blob {
        data: b"garbage".to_vec(),
    }))
    .unwrap();
    writer.write(&bytes).unwrap();
    writer.publish().unwrap();
    drop(guard);
    let pack = fs::read_dir(layout.objects_dir().join("pack"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "pack"))
        .unwrap();
    let mut bytes = fs::read(&pack).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&pack, bytes).unwrap();

    let records = layout.applied_packs_dir();
    fs::create_dir_all(&records).unwrap();
    let applied = records.join("origin");
    fs::write(&applied, "a".repeat(64)).unwrap();

    for dry_run in [true, false] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kit"));
        command
            .current_dir(dir.path())
            .args(["gc", "--grace-secs", "0"]);
        if dry_run {
            command.arg("-n");
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains("kept damaged local pack"), "{stderr}");
        assert_eq!(stderr.contains("packed payload"), dry_run, "{stderr}");
        assert!(!stderr.contains("local pack leftover"), "{stderr}");
        assert!(!stderr.contains("loose duplicate"), "{stderr}");
        assert!(pack.is_file());
        assert_eq!(applied.is_file(), dry_run);
    }
}

/// A repository with two old, wholly dead packs and nothing else.
fn two_dead_packs() -> (tempfile::TempDir, ObjectStore, Vec<std::path::PathBuf>) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    store.try_activate_local_packs().unwrap();
    let guard = store.prune_guard().unwrap();
    for n in 0..2 {
        let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
        writer
            .write(
                &serialize(&Object::Blob(Blob {
                    data: format!("garbage {n}").into_bytes(),
                }))
                .unwrap(),
            )
            .unwrap();
        writer.publish().unwrap();
    }
    drop(guard);
    let packs: Vec<_> = fs::read_dir(layout.objects_dir().join("pack"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    for path in &packs {
        fs::File::open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
    }
    (dir, store, packs)
}

#[test]
fn a_gc_that_cannot_take_the_lock_for_retirement_says_so_and_still_exits_zero() {
    let (dir, store, packs) = two_dead_packs();
    // A fetch, push or add in flight holds the shared lock.
    let writer = store.prune_guard().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kit"))
        .current_dir(dir.path())
        .arg("gc")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("gc stopped retiring local packs because a fetch, push or add held the store lock; 0 retired, the rest stay until the next gc"),
        "{stderr}"
    );
    assert_eq!(stderr.matches("stopped retiring").count(), 1, "{stderr}");
    assert!(packs.iter().all(|path| path.exists()));
    drop(writer);

    let output = Command::new(env!("CARGO_BIN_EXE_kit"))
        .current_dir(dir.path())
        .arg("gc")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(!stderr.contains("stopped retiring"), "{stderr}");
    assert!(
        stderr.contains("retired 2 wholly dead local pack"),
        "{stderr}"
    );
    assert!(packs.iter().all(|path| !path.exists()));
}
