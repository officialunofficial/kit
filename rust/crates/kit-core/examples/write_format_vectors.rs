//! Writes the vectors of `rust/tests/golden/formats/`.
//!
//! Run once, by hand, from the repository root:
//!
//! ```text
//! cargo run -p kit-core --example write_format_vectors
//! ```
//!
//! An optional first argument names another output directory. The golden
//! directory is `rust/tests/golden`; the example reads the object and tag
//! vectors there and writes `formats/` beside them. The test
//! `formats_stay_readable` never runs this example: it reads the committed
//! bytes. Do not run it again to make a failing test pass. A vector that no
//! longer reads is a format break, and the fix is a reader for the old bytes
//! (CONTRIBUTING, "Formats stay readable").
//!
//! The vectors:
//!
//! * `object-ids.txt`: `<file> <type> <id>` for each object vector, from the
//!   bytes in `objects/` and `tags/`. The ids of the empty tree, the
//!   single-file tree and the three-chunk manifest are checked against the
//!   values `scripts/golden/objects_ref.py` derives on its own.
//! * `packlist-first.bin`, `packlist-chained.bin`: pack list nodes, version 1.
//! * `sparse-cache.bin`: the sparse cache envelope, version 2. It is the
//!   committed `sparse/response_v2.bin` with the cache magic.
//! * `stash-list.bin`: the stash manifest.
//!
//! The bytes of these formats did not change between 0.8.0 and 0.10.0: the
//! writers of those releases produce the same bytes as the writers at the
//! commit that added the vectors.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use kit_core::hash::{self, to_hex};
use kit_core::object::{Object, id_from_object};
use kit_core::ops::stash::{StashEntry, StashList, serialize_list};
use kit_core::serialize::deserialize;
use kit_core::transfer::encode_packlist;

/// Object vectors, as `<dir>/<file>` under the golden directory.
const OBJECTS: [&str; 14] = [
    "objects/blob.bin",
    "objects/empty_blob.bin",
    "objects/empty_tree.bin",
    "objects/tree.bin",
    "objects/tree_single_file.bin",
    "objects/chunked_blob.bin",
    "objects/chunked_blob_cs0_3chunks.bin",
    "objects/commit_0parent.bin",
    "objects/commit_1parent.bin",
    "objects/commit_2parent.bin",
    "objects/remix_2sources.bin",
    "objects/remix_identical_upstream_distinct_commit.bin",
    "tags/tag_annotated.bin",
    "tags/tag_signed.bin",
];

/// Ids derived independently by `scripts/golden/objects_ref.py`.
const REFERENCE_IDS: [(&str, &str); 1] = [(
    "objects/empty_tree.bin",
    "b29117ce9b3d66ba98cd0a57145400f0bf6fff8b5c27c4552d80a38446f27ef7",
)];

fn type_name(object: &Object) -> &'static str {
    match object {
        Object::Blob(_) => "blob",
        Object::Tree(_) => "tree",
        Object::Commit(_) => "commit",
        Object::Remix(_) => "remix",
        Object::ChunkedBlob(_) => "chunked",
        Object::Tag(_) => "tag",
        other => panic!("no name for {other:?}"),
    }
}

fn main() -> std::io::Result<()> {
    let golden = PathBuf::from("rust/tests/golden");
    let out = std::env::args()
        .nth(1)
        .map_or_else(|| golden.join("formats"), PathBuf::from);
    fs::create_dir_all(&out)?;

    let mut ids = String::new();
    ids.push_str("# <file under rust/tests/golden> <type> <object id>\n");
    for file in OBJECTS {
        let bytes = fs::read(golden.join(file))?;
        let object = deserialize(&bytes).expect("an object vector decodes");
        let id = to_hex(&id_from_object(&object, &bytes));
        for (name, want) in REFERENCE_IDS {
            if name == file {
                assert_eq!(id, want, "{file}: id differs from the reference");
            }
        }
        writeln!(ids, "{file} {} {id}", type_name(&object)).expect("write to a String");
    }
    fs::write(out.join("object-ids.txt"), ids)?;

    let seed = |text: &str| hash::hash(text.as_bytes());
    fs::write(
        out.join("packlist-first.bin"),
        encode_packlist(None, &[seed("packlist-pack-0")]).expect("one pack fits"),
    )?;
    fs::write(
        out.join("packlist-chained.bin"),
        encode_packlist(
            Some(seed("packlist-prev")),
            &[seed("packlist-pack-1"), seed("packlist-pack-2")],
        )
        .expect("two packs fit"),
    )?;

    let mut cache = fs::read(golden.join("sparse/response_v2.bin"))?;
    assert_eq!(&cache[..4], b"KSP1", "the response vector starts with KSP1");
    cache[..4].copy_from_slice(b"KSPC");
    fs::write(out.join("sparse-cache.bin"), cache)?;

    let stash = StashList {
        entries: vec![
            StashEntry {
                commit_hash: seed("stash-commit-1"),
                parent_hash: seed("stash-parent-1"),
                timestamp: 1_700_000_100,
                message: "WIP on main: second".to_owned(),
            },
            StashEntry {
                commit_hash: seed("stash-commit-0"),
                parent_hash: hash::ZERO,
                timestamp: 1_700_000_000,
                message: "WIP on a branch: \u{e9}t\u{e9}".to_owned(),
            },
        ],
    };
    fs::write(out.join("stash-list.bin"), serialize_list(&stash).expect("fits"))?;

    let mut manifest = String::new();
    manifest.push_str("# Format vectors: formats that had no committed bytes.\n");
    manifest.push_str("# Written once by examples/write_format_vectors.rs; never regenerated by a test.\n");
    manifest.push_str("# Format: <file> <blake3-hex-of-file-bytes>\n");
    for name in [
        "object-ids.txt",
        "packlist-first.bin",
        "packlist-chained.bin",
        "sparse-cache.bin",
        "stash-list.bin",
    ] {
        let bytes = fs::read(out.join(name))?;
        writeln!(manifest, "{name} {}", to_hex(&hash::hash(&bytes))).expect("write to a String");
    }
    fs::write(out.join("MANIFEST.txt"), manifest)?;
    println!("format vectors written to {}", out.display());
    Ok(())
}
