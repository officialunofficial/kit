//! Local pack recovery through the command line.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use kit_core::hash::{Hash, to_hex};
use kit_core::layout::RepoLayout;
use kit_core::object::{Blob, Object};
use kit_core::refs;
use kit_core::serialize::serialize;
use kit_core::store::{LocalPackWriter, ObjectStore};

const PAYLOAD: &[u8] = b"packed object";
const REPAIR_HINT: &str = "kit closure repair-indexes";

struct PackedRepo {
    _dir: tempfile::TempDir,
    layout: RepoLayout,
    store: ObjectStore,
    id: Hash,
    pack: PathBuf,
    index: PathBuf,
}

impl PackedRepo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        store.try_activate_local_packs().unwrap();
        let guard = store.prune_guard().unwrap();
        let mut writer = LocalPackWriter::new(&store, &guard).unwrap();
        let id = writer.write(&blob(PAYLOAD)).unwrap();
        writer.publish().unwrap();
        drop(guard);
        let pack = fs::read_dir(layout.objects_dir().join("pack"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|ext| ext == "pack"))
            .unwrap();
        let index = pack.with_extension("idx");
        Self {
            _dir: dir,
            layout,
            store,
            id,
            pack,
            index,
        }
    }

    fn kit(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_kit"))
            .current_dir(self.layout.worktree_root())
            .args(args)
            .output()
            .unwrap()
    }

    fn repair(&self) -> Output {
        self.kit(&["closure", "repair-indexes"])
    }
}

fn blob(data: &[u8]) -> Vec<u8> {
    serialize(&Object::Blob(Blob {
        data: data.to_vec(),
    }))
    .unwrap()
}

fn assert_repair_hint(output: &Output, pair: &PackedRepo) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    let name = pair.pack.file_name().unwrap().to_str().unwrap();
    assert!(stderr.contains(name), "{stderr}");
    assert!(stderr.contains(REPAIR_HINT), "{stderr}");
}

#[test]
fn repair_rebuilds_a_bad_index_and_restores_reads() {
    let repo = PackedRepo::new();
    let expected = fs::read(&repo.index).unwrap();
    fs::write(&repo.index, b"damaged").unwrap();

    assert_repair_hint(&repo.kit(&["cat", &to_hex(&repo.id)]), &repo);
    assert_repair_hint(&repo.kit(&["cat", &to_hex(&[0; 32])]), &repo);
    assert_repair_hint(
        &repo.kit(&["closure", "verify", "HEAD", "--show-unreferenced"]),
        &repo,
    );
    assert_eq!(fs::read(&repo.index).unwrap(), b"damaged");

    let guard = repo.store.prune_guard().unwrap();
    let busy = repo.repair();
    let stderr = String::from_utf8_lossy(&busy.stderr);
    assert!(!busy.status.success(), "{stderr}");
    assert!(stderr.contains("format lock"), "{stderr}");
    assert_eq!(fs::read(&repo.index).unwrap(), b"damaged");
    drop(guard);

    let repaired = repo.repair();
    assert!(
        repaired.status.success(),
        "{}",
        String::from_utf8_lossy(&repaired.stderr)
    );
    assert_eq!(repaired.stdout, b"Rebuilt 1 local pack index.\n");
    assert_eq!(fs::read(&repo.index).unwrap(), expected);
    let read = repo.kit(&["cat", &to_hex(&repo.id)]);
    assert!(read.status.success());
    assert_eq!(read.stdout, PAYLOAD);
    let missing = repo.kit(&["cat", &to_hex(&[0; 32])]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("not found"));
    let repeated = repo.repair();
    assert!(repeated.status.success());
    assert_eq!(repeated.stdout, b"Rebuilt 0 local pack indexes.\n");
}

#[test]
fn repair_keeps_a_bad_pack_and_clears_fetch_records_for_refetch() {
    let repo = PackedRepo::new();
    let mut pack = fs::read(&repo.pack).unwrap();
    let payload = pack
        .windows(PAYLOAD.len())
        .position(|bytes| bytes == PAYLOAD)
        .unwrap();
    pack[payload] ^= 1;
    fs::write(&repo.pack, &pack).unwrap();
    fs::write(&repo.index, b"damaged").unwrap();
    let records = repo.layout.applied_packs_dir();
    fs::create_dir_all(&records).unwrap();
    let applied = records.join("origin");
    fs::write(&applied, "a".repeat(64)).unwrap();

    let output = repo.repair();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("invalid pack trailer"), "{stderr}");
    assert!(stderr.contains("kit fetch"), "{stderr}");
    assert_eq!(fs::read(&repo.pack).unwrap(), pack);
    assert_eq!(fs::read(&repo.index).unwrap(), b"damaged");
    assert!(!applied.exists());
}

#[test]
fn gc_aborts_before_deleting_objects_when_a_pack_index_is_damaged() {
    let repo = PackedRepo::new();
    let pack = fs::read(&repo.pack).unwrap();
    fs::write(&repo.index, b"damaged").unwrap();
    let loose = blob(b"unreachable loose object");
    let loose_id = repo.store.write(&loose).unwrap();

    assert_repair_hint(&repo.kit(&["gc", "--grace-secs", "0"]), &repo);
    assert_eq!(repo.store.read(&loose_id).unwrap(), loose);
    assert_eq!(fs::read(&repo.pack).unwrap(), pack);
    assert_eq!(fs::read(&repo.index).unwrap(), b"damaged");
}
