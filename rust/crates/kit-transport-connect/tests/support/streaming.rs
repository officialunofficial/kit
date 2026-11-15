//! Client-side helpers for the pack streaming tests: a signer, a
//! `ClientSource` over native HTTP to the loopback server, and a remote
//! seeded with one commit.
#![allow(dead_code)] // each test binary uses part of the helpers

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use kit_client::{Client, Destination, Signer};
use kit_core::hash::{self, Hash};
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::pack::{self, PackWriter};
use kit_core::protocol::{PackKey, SliceBody, Transport};
use kit_core::refs::RefWriteCondition;
use kit_core::sign::{self, KeyPair};
use kit_core::{serialize, transfer};
use kit_sync::{CloneRemote, NativeClock, NativeHttp, init_clone_dir};
use kit_transport_file::FileTransport;

pub const MIB: usize = 1 << 20;

pub struct Dalek(SigningKey);

impl Dalek {
    pub fn new() -> Self {
        Self(SigningKey::from_bytes(&[7; 32]))
    }
}

impl Signer for Dalek {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String> {
        Ok(self.0.sign(digest).to_bytes())
    }
}

/// Native HTTP that may fetch loopback HTTP pack locations.
pub fn http() -> NativeHttp {
    NativeHttp::new()
        .unwrap()
        .with_test_pack_location_http(true)
        .allow_private_pack_locations(true)
}

pub type TestClient<'a> = Client<'a, NativeHttp, Dalek, NativeClock>;

pub fn client<'a>(http: &'a NativeHttp, signer: &'a Dalek, origin: &str) -> TestClient<'a> {
    Client::signed(
        http,
        Destination::new(origin.to_owned(), "default".to_owned()).unwrap(),
        signer,
        &NativeClock,
    )
}

/// Bytes that do not compress.
pub fn noise(len: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block = 0u32;
    while out.len() < len {
        out.extend_from_slice(&hash::hash(&[&block.to_le_bytes()[..], &[seed]].concat()));
        block += 1;
    }
    out.truncate(len);
    out
}

/// What [`seed`] stored.
pub struct Seeded {
    pub tip: Hash,
    pub pack: Hash,
    pub node: Hash,
    pub pack_len: u64,
}

/// Store in `remote` one signed commit of one file of `len` noise bytes, in
/// one pack, with its packmap node, and point `main` at it.
pub fn seed(remote: &FileTransport, len: usize) -> Seeded {
    let blob = Object::Blob(Blob {
        data: noise(len, 7),
    });
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: b"big.bin".to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob.id().unwrap(),
        }],
    });
    let key = KeyPair::generate().unwrap();
    let mut commit = Commit::new_unannotated(
        tree.id().unwrap(),
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"big file".to_vec(),
        1_700_000_000,
        [0u8; 64],
    );
    commit.signature = sign::sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let mut writer = PackWriter::new();
    for object in [&blob, &tree, &commit] {
        writer
            .push_raw(object.id().unwrap(), &serialize::serialize(object).unwrap())
            .unwrap();
    }
    let bytes = writer.finish().unwrap();
    let pack = pack::pack_key(&bytes);
    remote
        .upload_pack(&SliceBody(&bytes), &PackKey::new(pack), None)
        .unwrap();
    let node = transfer::encode_packlist(None, &[pack]).unwrap();
    let node_key = hash::hash(&node);
    remote
        .upload_blob(&node, &PackKey::new(node_key), None)
        .unwrap();
    remote
        .update_ref(
            "refs/kit/packmap/main",
            RefWriteCondition::Missing,
            &node_key,
        )
        .unwrap();
    let tip = commit.id().unwrap();
    remote
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &tip)
        .unwrap();
    Seeded {
        tip,
        pack,
        node: node_key,
        pack_len: bytes.len() as u64,
    }
}

pub fn clone_remote() -> CloneRemote {
    CloneRemote {
        name: "origin".to_owned(),
        url: "kit+https://example.invalid/default".to_owned(),
        kind: "kit".to_owned(),
    }
}

/// An empty clone directory at `dir/name`.
pub fn target(dir: &Path, name: &str) -> PathBuf {
    let work = dir.join(name);
    init_clone_dir(&work, &clone_remote()).unwrap();
    work
}

/// Fill `out` with incompressible bytes from `seed`.
fn noise_into(seed: u64, out: &mut [u8]) {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for chunk in out.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
}

/// Commit `files` files of `len` incompressible bytes in 256 directories
/// to the store of `work`, one file at a time, and point `main` and HEAD
/// at the commit.
pub fn commit_files(work: &Path, files: usize, len: usize) -> Hash {
    let layout = kit_core::layout::RepoLayout::single(work);
    let store = kit_core::store::ObjectStore::open(&layout).unwrap();
    let batch = store.batch();
    let mut dirs = Vec::new();
    for dir in 0..256usize {
        let mut entries = Vec::new();
        for file in (dir..files).step_by(256) {
            let mut data = vec![0u8; len];
            noise_into(file as u64, &mut data);
            let blob = Object::Blob(Blob { data });
            entries.push(TreeEntry {
                name: format!("f{file:06}").into_bytes(),
                mode: EntryMode::Blob,
                object_hash: batch.write(&serialize::serialize(&blob).unwrap()).unwrap(),
            });
        }
        if entries.is_empty() {
            continue;
        }
        let tree = Object::Tree(Tree { entries });
        dirs.push(TreeEntry {
            name: format!("d{dir:03}").into_bytes(),
            mode: EntryMode::Tree,
            object_hash: batch.write(&serialize::serialize(&tree).unwrap()).unwrap(),
        });
    }
    let root = Object::Tree(Tree { entries: dirs });
    let root = batch.write(&serialize::serialize(&root).unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut commit = Commit::new_unannotated(
        root,
        Vec::new(),
        Identity::ed25519(key.public.0),
        key.public.0,
        b"many files".to_vec(),
        1_700_000_000,
        [0u8; 64],
    );
    commit.signature = sign::sign_commit(&commit, &key).unwrap().0;
    let tip = batch
        .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap();
    batch.commit().unwrap();
    kit_core::refs::write_ref(&layout, "main", &tip).unwrap();
    kit_core::refs::write_head_branch(&layout, "main").unwrap();
    tip
}

/// The entries of a pack of `files` files in 256 directories: the blobs,
/// the trees and the commit.
pub fn entries_of(files: usize) -> usize {
    files + files.min(256) + 2
}
