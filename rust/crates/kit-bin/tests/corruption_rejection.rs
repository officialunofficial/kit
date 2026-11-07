//! Fault injection — corrupted-object / invalid-ref rejection.
//!
//! Mutate on-disk artifacts (loose objects, ref files, HEAD, signatures) and
//! assert the reading command rejects them **cleanly**: an allowlisted non-OK
//! exit, no panic, and never a silent success. The validator unit test proved
//! *detection* on read (`validator_detects_tampered_object`); this proves the **CLI commands**
//! surface corruption as documented errors rather than crashing — the gap the
//! pre-open-source audit flagged (only the bit-flip case was covered before).
//!
//! Two families:
//!   * **hash-mismatch** — corrupt an existing object/ref in place; the read
//!     fails content-addressing / ref decode.
//!   * **deserialize** — write a *content-addressed* garbage object (bytes whose
//!     BLAKE3 matches the path) so it passes content-addressing and then fails
//!     to decode (bad magic / truncated / bad type).
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::path::PathBuf;

use common::{Repo, check_exit};
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::serialize::serialize;
use kit_core::store::ObjectStore;
use kit_core::{hash, refs, to_hex};

/// A repo with one commit and one annotated (signed) tag.
fn committed_repo() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"hello\n", "first");
    repo.ok(&["tag", "-a", "v1", "-m", "release"]);
    repo
}

fn object_file(repo: &Repo, hex: &str) -> PathBuf {
    repo.kit_dir()
        .join("objects")
        .join(&hex[..2])
        .join(&hex[2..])
}

/// Run a reading command and assert it rejected corruption cleanly: exit in the
/// allowlist (no panic / no signal), and NOT a success.
fn assert_rejected(repo: &Repo, args: &[&str], case: &str) {
    let out = repo.run(args);
    check_exit(&out, case).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert!(
        !out.status.success(),
        "{case}: expected `kit {}` to reject corruption, but it exited 0\nstdout: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Run a command and assert it SUCCEEDED (for accepted inputs).
fn assert_accepted(repo: &Repo, args: &[&str], case: &str) {
    let out = repo.run(args);
    check_exit(&out, case).unwrap_or_else(|e| panic!("{case}: {e}"));
    assert!(
        out.status.success(),
        "{case}: expected `kit {}` to be accepted, but it failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Object corruption — hash-mismatch family (corrupt an existing object)
// ---------------------------------------------------------------------------

#[test]
fn flipped_object_byte_is_rejected() {
    let repo = committed_repo();
    let head = to_hex(
        &refs::resolve_head(&RepoLayout::single(repo.path()))
            .unwrap()
            .unwrap(),
    );
    let path = object_file(&repo, &head);
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&path, &bytes).unwrap();
    assert_rejected(&repo, &["cat-file", &head], "flipped object byte");
}

#[test]
fn truncated_object_is_rejected() {
    let repo = committed_repo();
    let head = to_hex(
        &refs::resolve_head(&RepoLayout::single(repo.path()))
            .unwrap()
            .unwrap(),
    );
    let path = object_file(&repo, &head);
    fs::write(&path, b"\x03MK").unwrap(); // 3 bytes — shorter than the prologue
    assert_rejected(&repo, &["cat-file", &head], "truncated object");
}

// ---------------------------------------------------------------------------
// Object corruption — deserialize family (content-addressed garbage)
// ---------------------------------------------------------------------------

/// Write raw bytes at their own BLAKE3 path so they pass content-addressing,
/// returning the hex hash to address them by.
fn write_raw_object(repo: &Repo, bytes: &[u8]) -> String {
    let hex = to_hex(&hash::hash(bytes));
    let path = object_file(repo, &hex);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    hex
}

#[test]
fn content_addressed_garbage_is_rejected_on_decode() {
    // Each variant loads past content-addressing, then must fail to decode.
    let cases: &[(&str, Vec<u8>)] = &[
        ("empty", Vec::new()),
        ("short-prologue", vec![0x03, b'K', b'O']),
        ("bad-magic", {
            let mut v = vec![0x03];
            v.extend_from_slice(b"XXXX");
            v.push(0x01);
            v
        }),
        ("bad-type", {
            let mut v = vec![0x09]; // 0x09 is not a valid ObjectType
            v.extend_from_slice(b"KOB1");
            v.push(0x01);
            v
        }),
    ];
    for (name, bytes) in cases {
        let repo = committed_repo();
        let hex = write_raw_object(&repo, bytes);
        assert_rejected(&repo, &["cat-file", &hex], &format!("decode/{name}"));
    }
}

// ---------------------------------------------------------------------------
// Ref / HEAD corruption
// ---------------------------------------------------------------------------

#[test]
fn malformed_branch_ref_is_rejected() {
    let valid = {
        let repo = committed_repo();
        fs::read_to_string(repo.kit_dir().join("refs/heads/main")).unwrap()
    };
    let good64 = valid.trim_end().to_owned();
    assert_eq!(good64.len(), 64);

    let cases: &[(&str, String)] = &[
        ("uppercase-hex", format!("{}\n", good64.to_uppercase())),
        ("too-short", format!("{}\n", &good64[..32])),
        ("non-hex", format!("{}\n", "z".repeat(64))),
        ("too-long", format!("{good64}{good64}\n")),
    ];
    for (name, contents) in cases {
        let repo = committed_repo();
        fs::write(repo.kit_dir().join("refs/heads/main"), contents).unwrap();
        // Drive the STRICT ref reader: `gc`'s `collect_roots` fails closed on an
        // undecodable ref. (Porcelain like `log` is intentionally lenient — a
        // malformed ref reads as `None`, i.e. an unborn branch — so it is the
        // wrong oracle for ref corruption.)
        assert_rejected(&repo, &["gc"], &format!("ref/{name}"));
    }
}

#[test]
fn branch_ref_without_trailing_newline_is_accepted() {
    // `decode_ref_wire` trims optional trailing whitespace, so a 64-hex ref with
    // NO trailing newline is valid, not a corruption.
    let repo = committed_repo();
    let p = repo.kit_dir().join("refs/heads/main");
    let good64 = fs::read_to_string(&p).unwrap().trim_end().to_owned();
    fs::write(&p, &good64).unwrap(); // no '\n'
    // Drive the STRICT ref reader (`gc`/`collect_roots`), not lenient `log`:
    // lenient porcelain can exit 0 on a ref it failed to resolve, which would
    // mask a strict-decode regression that started rejecting newline-less refs.
    assert_accepted(&repo, &["gc"], "ref/no-trailing-newline");
}

#[test]
fn malformed_head_is_rejected() {
    let repo = committed_repo();
    fs::write(repo.kit_dir().join("HEAD"), b"this is not a head\n").unwrap();
    assert_rejected(&repo, &["status"], "HEAD/garbage");
}

// ---------------------------------------------------------------------------
// Signature tampering (content-valid object, invalid signature)
// ---------------------------------------------------------------------------

#[test]
fn tampered_commit_signature_is_rejected_by_verify() {
    let repo = committed_repo();
    let layout = RepoLayout::single(repo.path());
    let head = refs::resolve_head(&layout).unwrap().unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    let Object::Commit(mut c) = store.read_object(&head).unwrap() else {
        panic!("HEAD is not a commit");
    };
    c.signature[0] ^= 0xff; // valid bytes, invalid signature
    let bytes = serialize(&Object::Commit(c)).unwrap();
    let new = store.write(&bytes).unwrap(); // re-store at its (new) content hash
    let hex = to_hex(&new);
    assert_rejected(&repo, &["verify", &hex], "tampered commit signature");
}

#[test]
fn tampered_tag_signature_is_rejected_by_verify() {
    let repo = committed_repo();
    let layout = RepoLayout::single(repo.path());
    let tag_hash = refs::read_tag(&layout, "v1")
        .unwrap()
        .expect("annotated tag v1 ref");
    let store = ObjectStore::open(&layout).unwrap();
    let Object::Tag(mut t) = store.read_object(&tag_hash).unwrap() else {
        panic!("v1 is not an annotated tag object");
    };
    t.signature[0] ^= 0xff;
    let bytes = serialize(&Object::Tag(t)).unwrap();
    let new = store.write(&bytes).unwrap();
    let hex = to_hex(&new);
    assert_rejected(&repo, &["verify", &hex], "tampered tag signature");
}

// ---------------------------------------------------------------------------
// Rebase over an unreadable commit
// ---------------------------------------------------------------------------

/// main = base - O1 - O2; feature = base - A - B - C, checked out. Returns the
/// hex ids of O1 and B.
fn rebase_fixture(repo: &Repo) -> (String, String) {
    repo.commit_file("base.txt", b"base\n", "base");
    repo.ok(&["branch", "feature"]);
    repo.commit_file("o1.txt", b"o1\n", "O1");
    let o1 = String::from_utf8(repo.ok(&["rev-parse", "HEAD"]).stdout).unwrap();
    repo.commit_file("o2.txt", b"o2\n", "O2");
    repo.ok(&["checkout", "feature"]);
    repo.commit_file("a.txt", b"a\n", "A");
    repo.commit_file("b.txt", b"b\n", "B");
    let b = String::from_utf8(repo.ok(&["rev-parse", "HEAD"]).stdout).unwrap();
    repo.commit_file("c.txt", b"c\n", "C");
    (o1.trim().to_owned(), b.trim().to_owned())
}

/// `kit rebase main` fails and leaves the branch, `HEAD`, the files and the
/// rebase state as they were.
fn assert_rebase_changes_nothing(repo: &Repo, case: &str) {
    let layout = RepoLayout::single(repo.path());
    let tip = refs::read_ref(&layout, "feature").unwrap();
    assert_rejected(repo, &["rebase", "main"], case);
    assert_eq!(
        fs::read_to_string(repo.kit_dir().join("HEAD")).unwrap(),
        "ref: refs/heads/feature\n",
        "{case}: HEAD moved"
    );
    assert_eq!(refs::read_ref(&layout, "feature").unwrap(), tip, "{case}");
    assert!(
        common::operation_residue(&repo.kit_dir(), "rebase").is_none(),
        "{case}: rebase state left behind"
    );
    for (file, present) in [("a.txt", true), ("c.txt", true), ("o2.txt", false)] {
        assert_eq!(repo.path().join(file).exists(), present, "{case}: {file}");
    }
}

#[test]
fn rebase_over_an_unreadable_commit_fails_and_changes_nothing() {
    let repo = Repo::new();
    let (_, b) = rebase_fixture(&repo);
    fs::remove_file(object_file(&repo, &b)).unwrap();
    assert_rebase_changes_nothing(&repo, "missing commit in the branch");

    let repo = Repo::new();
    let (_, b) = rebase_fixture(&repo);
    let path = object_file(&repo, &b);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&path, &bytes).unwrap();
    assert_rebase_changes_nothing(&repo, "corrupt commit in the branch");

    // Without O1 the ancestors of main would lack `base`, and the rebase
    // would replay `base` again.
    let repo = Repo::new();
    let (o1, _) = rebase_fixture(&repo);
    fs::remove_file(object_file(&repo, &o1)).unwrap();
    assert_rebase_changes_nothing(&repo, "missing commit in the base");
}

// ---------------------------------------------------------------------------
// History walks over an unreadable commit
// ---------------------------------------------------------------------------

/// main = r - p - m - g; side = r - p - x - merge(x, g), checked out. Returns
/// the hex ids of m and g.
fn range_fixture(repo: &Repo) -> (String, String) {
    let head = |repo: &Repo| {
        let out = repo.ok(&["rev-parse", "HEAD"]).stdout;
        String::from_utf8(out).unwrap().trim().to_owned()
    };
    repo.commit_file("r.txt", b"r\n", "r");
    repo.commit_file("p.txt", b"p\n", "p");
    repo.ok(&["branch", "side"]);
    repo.commit_file("m.txt", b"m\n", "m");
    let m = head(repo);
    repo.commit_file("g.txt", b"g\n", "g");
    let g = head(repo);
    repo.ok(&["checkout", "side"]);
    repo.commit_file("x.txt", b"x\n", "x");
    repo.ok(&["merge", "main"]);
    (m, g)
}

/// Flip the last byte of the loose object `hex`.
fn corrupt_object(repo: &Repo, hex: &str) {
    let path = object_file(repo, hex);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&path, &bytes).unwrap();
}

/// Run `kit <args>` and assert it fails and prints nothing to stdout.
fn assert_rejected_silently(repo: &Repo, args: &[&str], case: &str) {
    assert_rejected(repo, args, case);
    let out = repo.run(args);
    assert!(out.stdout.is_empty(), "{case}: printed a partial answer");
}

#[test]
fn a_log_range_over_an_unreadable_commit_fails_and_prints_nothing() {
    let repo = Repo::new();
    range_fixture(&repo);
    let healthy = repo.ok(&["log", "--oneline", "main..side"]).stdout;
    let subjects: Vec<String> = String::from_utf8(healthy)
        .unwrap()
        .lines()
        .map(|line| line.split_once(' ').unwrap().1.to_owned())
        .collect();
    assert_eq!(subjects, ["Merge branch 'main'", "x"]);

    // Without m the excluded side would lack p and r, and the range would
    // print them.
    let repo = Repo::new();
    let (m, _) = range_fixture(&repo);
    fs::remove_file(object_file(&repo, &m)).unwrap();
    for range in ["main..side", "side...main"] {
        assert_rejected_silently(
            &repo,
            &["log", range],
            "missing commit on the excluded side",
        );
    }

    let repo = Repo::new();
    let (m, _) = range_fixture(&repo);
    corrupt_object(&repo, &m);
    assert_rejected_silently(
        &repo,
        &["log", "main..side"],
        "corrupt commit on the excluded side",
    );
}

#[test]
fn bisect_over_an_unreadable_commit_fails_and_offers_nothing() {
    let bisect = |repo: &Repo, good: &str| {
        repo.ok(&["bisect", "start"]);
        repo.ok(&["bisect", "bad"]);
        repo.run(&["bisect", "good", good])
    };
    let repo = Repo::new();
    let (_, g) = range_fixture(&repo);
    let out = bisect(&repo, &g);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("(2 candidates remaining)"));

    // Without m the good set would lack p and r, and bisect would offer them
    // although they are known good.
    let repo = Repo::new();
    let (m, g) = range_fixture(&repo);
    fs::remove_file(object_file(&repo, &m)).unwrap();
    let out = bisect(&repo, &g);
    check_exit(&out, "missing commit in the good set").unwrap();
    assert!(!out.status.success(), "missing commit in the good set");
    assert!(out.stdout.is_empty(), "offered a candidate");

    let repo = Repo::new();
    let (m, g) = range_fixture(&repo);
    corrupt_object(&repo, &m);
    let out = bisect(&repo, &g);
    check_exit(&out, "corrupt commit in the good set").unwrap();
    assert!(!out.status.success(), "corrupt commit in the good set");
    assert!(out.stdout.is_empty(), "offered a candidate");
}

#[test]
fn a_patch_series_over_an_unreadable_commit_fails_and_writes_nothing() {
    let repo = Repo::new();
    range_fixture(&repo);
    let healthy = repo
        .ok(&["git", "format-patch", "--stdout", "main..side"])
        .stdout;
    let healthy = String::from_utf8(healthy).unwrap();
    assert_eq!(healthy.matches("\nSubject: ").count(), 1, "{healthy}");
    assert!(healthy.contains("\nSubject: [PATCH] x\n"), "{healthy}");

    // Without m the excluded side would lack p and r, and the series would
    // hold patches for them.
    let repo = Repo::new();
    let (m, _) = range_fixture(&repo);
    fs::remove_file(object_file(&repo, &m)).unwrap();
    let args = ["git", "format-patch", "--stdout", "main..side"];
    assert_rejected_silently(&repo, &args, "missing commit on the excluded side");

    let repo = Repo::new();
    let (m, _) = range_fixture(&repo);
    corrupt_object(&repo, &m);
    assert_rejected_silently(&repo, &args, "corrupt commit on the excluded side");
}

/// Write a commit on top of main whose second parent is main's tree, and
/// return its hex id.
fn commit_above_a_tree(repo: &Repo) -> String {
    let layout = RepoLayout::single(repo.path());
    let store = ObjectStore::open(&layout).unwrap();
    let main = refs::read_ref(&layout, "main").unwrap().unwrap();
    let Object::Commit(c) = store.read_object(&main).unwrap() else {
        panic!("main is not a commit");
    };
    let odd = kit_core::object::Commit::new_unannotated(
        c.tree_hash,
        vec![main, c.tree_hash],
        c.author.clone(),
        c.signer,
        b"odd".to_vec(),
        c.timestamp + 1,
        [0; 64],
    );
    to_hex(
        &store
            .write(&serialize(&Object::Commit(odd)).unwrap())
            .unwrap(),
    )
}

#[test]
fn a_range_over_a_parent_that_is_not_a_commit_fails() {
    let repo = Repo::new();
    range_fixture(&repo);
    let range = format!("{}..side", commit_above_a_tree(&repo));
    let case = "a parent on the excluded side that is not a commit";
    assert_rejected_silently(&repo, &["log", &range], case);
    let args = ["git", "format-patch", "--stdout", &range];
    assert_rejected_silently(&repo, &args, case);
}
