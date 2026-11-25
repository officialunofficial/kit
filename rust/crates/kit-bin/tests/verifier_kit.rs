//! End-to-end CLI coverage for `prove` / `verify-proof` / `closure`
//! (verifier kit).
#![allow(clippy::unwrap_used)]

mod common;

use std::fs;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{KEY_SEED, Repo};
use kit_core::hash::to_hex_bytes;
use kit_core::layout::RepoLayout;
use kit_core::object::Object;
use kit_core::serialize::serialize;
use kit_core::sign::KeyPair;
use kit_core::store::ObjectStore;
use kit_core::verify::MAX_BUNDLE_BYTES;

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn head(repo: &Repo) -> String {
    stdout(&repo.ok(&["rev-parse", "HEAD"])).trim().to_owned()
}

fn signer_hex() -> String {
    let kp = KeyPair::from_seed(KEY_SEED);
    to_hex_bytes(&kp.public.0)
}

fn write_trust_roots(path: &std::path::Path, pubkey_hex: &str) {
    fs::write(
        path,
        format!(
            "[[trust_root]]\nkeyid = \"ed25519:{pubkey_hex}\"\nkind = \"ed25519\"\npubkey_hex = \"{pubkey_hex}\"\n"
        ),
    )
    .unwrap();
}

fn json_has(text: &str, key: &str) -> bool {
    text.contains(&format!("\"{key}\""))
}

fn fixture_repo() -> Repo {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"hello proof\n", "small");
    repo.write("src/nested.txt", b"nested body\n");
    repo.ok(&["add", "src/nested.txt"]);
    repo.ok(&["commit", "-m", "nested"]);
    repo
}

#[test]
fn prove_verify_root_tree() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "-o", "root.kdpb"]);
    let out = repo.ok(&["verify-proof", &commit, "root.kdpb"]);
    let text = stdout(&out);
    assert!(text.starts_with("ok: object / @"), "got: {text}");
    assert!(text.contains("valid signature"), "{text}");
}

#[test]
fn prove_verify_small_file() {
    let repo = fixture_repo();
    let commit = head(&repo);
    let out = repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.kdpb"]);
    let status = stdout(&out);
    assert!(status.contains("proof:"), "{status}");
    assert!(status.contains("a.txt"), "{status}");
    let out = repo.ok(&["verify-proof", &commit, "a.kdpb", "--expect-path", "a.txt"]);
    let text = stdout(&out);
    assert!(text.contains("ok: object a.txt"), "{text}");
}

#[test]
fn prove_verify_nested_file() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "src/nested.txt", "-o", "n.kdpb"]);
    let out = repo.ok(&[
        "verify-proof",
        &commit,
        "n.kdpb",
        "--expect-path",
        "src/nested.txt",
    ]);
    assert!(stdout(&out).contains("ok: object src/nested.txt"));
}

#[test]
fn prove_verify_chunk_and_range() {
    let repo = fixture_repo();
    let mut big = vec![0u8; 3 * 1024 * 1024];
    let mut x = 0u8;
    for b in &mut big {
        *b = x;
        x = x.wrapping_add(1);
    }
    repo.write("big.bin", &big);
    repo.ok(&["add", "big.bin"]);
    repo.ok(&["commit", "-m", "chunked"]);
    let commit = head(&repo);

    repo.ok(&["prove", "HEAD", "big.bin", "--chunk", "0", "-o", "c.kdpb"]);
    let out = repo.ok(&["verify-proof", &commit, "c.kdpb"]);
    assert!(
        stdout(&out).contains("ok: chunk big.bin"),
        "{}",
        stdout(&out)
    );

    repo.ok(&[
        "prove", "HEAD", "big.bin", "--range", "0:100", "-o", "r.kdpb",
    ]);
    let out = repo.ok(&[
        "verify-proof",
        &commit,
        "r.kdpb",
        "--payload-out",
        "slice.bin",
    ]);
    assert!(
        stdout(&out).contains("ok: range big.bin"),
        "{}",
        stdout(&out)
    );
    let got = fs::read(repo.path().join("slice.bin")).unwrap();
    assert_eq!(got, &big[..100]);

    repo.ok(&[
        "prove", "HEAD", "big.bin", "--range", "0:100", "-o", "ro.kdpb",
    ]);
    let out = repo.ok(&["verify-proof", &commit, "ro.kdpb"]);
    assert!(
        stdout(&out).contains("ok: range big.bin"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn expect_path_mismatch_is_dataerr() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.kdpb"]);
    let out = repo.run(&[
        "verify-proof",
        &commit,
        "a.kdpb",
        "--expect-path",
        "other.txt",
    ]);
    assert_eq!(out.status.code(), Some(65));
    assert!(
        stdout(&out).contains("bad: authenticated path"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn tampered_bundle_fails() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.kdpb"]);
    let path = repo.path().join("a.kdpb");
    let mut bytes = fs::read(&path).unwrap();
    let i = bytes.len() / 2;
    bytes[i] ^= 0xff;
    fs::write(&path, bytes).unwrap();
    let out = repo.run(&["verify-proof", &commit, "a.kdpb"]);
    assert_eq!(out.status.code(), Some(65));
    assert!(stdout(&out).contains("bad:"), "{}", stdout(&out));
}

/// Store a copy of HEAD whose signature does not verify and return its id.
fn forged_head(repo: &Repo) -> String {
    let layout = RepoLayout::single(repo.path());
    let head = kit_core::refs::resolve_head(&layout).unwrap().unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    let Object::Commit(mut c) = store.read_object(&head).unwrap() else {
        panic!("HEAD is not a commit");
    };
    c.signature[0] ^= 0xff;
    let id = store
        .write(&serialize(&Object::Commit(c)).unwrap())
        .unwrap();
    kit_core::to_hex(&id)
}

#[test]
fn invalid_signature_is_dataerr_without_trust_roots() {
    let repo = fixture_repo();
    let forged = forged_head(&repo);
    repo.ok(&["prove", &forged, "a.txt", "-o", "a.kdpb"]);

    let out = repo.run(&["verify-proof", &forged, "a.kdpb", "--payload-out", "p.out"]);
    assert_eq!(out.status.code(), Some(65), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.starts_with("bad: "), "{text}");
    assert!(text.contains("INVALID signature"), "{text}");
    assert!(!text.contains("ok:"), "{text}");
    assert!(!repo.path().join("p.out").exists());

    let out = repo.run(&["verify-proof", &forged, "a.kdpb", "--format=json"]);
    assert_eq!(out.status.code(), Some(65));
    assert!(
        stdout(&out).contains("\"signature_valid\":false"),
        "{}",
        stdout(&out)
    );
    assert!(stderr(&out).starts_with("bad: "), "{}", stderr(&out));
}

#[test]
fn trusted_signer_and_unlisted() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.kdpb"]);
    let hex = signer_hex();
    let good = repo.path().join("good.toml");
    write_trust_roots(&good, &hex);
    let out = repo.ok(&[
        "verify-proof",
        &commit,
        "a.kdpb",
        "--trusted",
        "--trust-roots",
        good.to_str().unwrap(),
    ]);
    assert!(stdout(&out).contains("signer trusted"), "{}", stdout(&out));

    let bad = repo.path().join("bad.toml");
    write_trust_roots(&bad, &"99".repeat(32));
    let out = repo.run(&[
        "verify-proof",
        &commit,
        "a.kdpb",
        "--trusted",
        "--trust-roots",
        bad.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(65));
    assert!(
        stdout(&out).contains("not in the trust-roots registry"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn prove_and_verify_json_keys() {
    let repo = fixture_repo();
    let commit = head(&repo);
    let out = repo.ok(&["prove", "HEAD", "a.txt", "-o", "a.kdpb", "--format=json"]);
    let js = stdout(&out);
    for key in [
        "commit_id",
        "path",
        "selector",
        "bundle_bytes",
        "bundle_blake3",
        "output",
    ] {
        assert!(json_has(&js, key), "prove json missing {key}: {js}");
    }
    let out = repo.ok(&["verify-proof", &commit, "a.kdpb", "--format=json"]);
    let js = stdout(&out);
    for key in [
        "commit_id",
        "tree_hash",
        "path",
        "leaf_id",
        "signer",
        "signature_valid",
        "payload",
        "signer_trusted",
        "step_inner_roots",
        "chunk_inner_root",
    ] {
        assert!(json_has(&js, key), "verify-proof json missing {key}: {js}");
    }
}

/// The JSON of `verify-proof` describes the payload it disclosed: its kind,
/// its length and the BLAKE3 of exactly the bytes `--payload-out` writes,
/// then the fields that place it in the file.
#[test]
fn verify_proof_json_describes_each_kind_of_payload() {
    let repo = fixture_repo();
    let mut big = vec![0u8; 3 * 1024 * 1024];
    let mut x = 0u8;
    for b in &mut big {
        *b = x;
        x = x.wrapping_add(1);
    }
    repo.write("big.bin", &big);
    repo.ok(&["add", "big.bin"]);
    repo.ok(&["commit", "-m", "chunked"]);
    let commit = head(&repo);

    let cases: [(&str, &[&str], &str, &[&str]); 3] = [
        ("object", &[], "a.txt", &[]),
        (
            "chunk",
            &["--chunk", "0"],
            "big.bin",
            &["\"index\":0", "\"total_size\":3145728", "\"start\":0"],
        ),
        (
            "range",
            &["--range", "0:100"],
            "big.bin",
            &["\"offset_in_blob\":", "\"absolute_offset\":0"],
        ),
    ];
    for (kind, selector, path, fields) in cases {
        let proof = format!("{kind}.kdpb");
        let payload = format!("{kind}.payload");
        let mut prove = vec!["prove", "HEAD", path];
        prove.extend_from_slice(selector);
        prove.extend(["-o", proof.as_str()]);
        repo.ok(&prove);
        let out = repo.ok(&[
            "verify-proof",
            &commit,
            &proof,
            "--payload-out",
            &payload,
            "--format=json",
        ]);
        let js = stdout(&out);
        let bytes = fs::read(repo.path().join(&payload)).unwrap();
        let expected = format!(
            "\"payload\":{{\"kind\":\"{kind}\",\"bytes_len\":{},\"bytes_blake3\":\"{}\"",
            bytes.len(),
            kit_core::hash::to_hex(&kit_core::hash::hash(&bytes)),
        );
        assert!(
            js.contains(&expected),
            "{kind}: expected {expected} in {js}"
        );
        for field in fields {
            assert!(js.contains(field), "{kind}: missing {field} in {js}");
        }
    }
}

#[test]
fn closure_export_verify_roundtrip() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["closure", "export", "HEAD", "-o", "snap.closure"]);
    let out = repo.ok(&["closure", "verify", &commit, "--from", "snap.closure"]);
    assert!(
        stdout(&out).contains("ok: closure complete"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("snapshot"), "{}", stdout(&out));

    repo.ok(&[
        "closure",
        "export",
        "HEAD",
        "--history",
        "-o",
        "hist.closure",
    ]);
    let out = repo.ok(&[
        "closure",
        "verify",
        &commit,
        "--from",
        "hist.closure",
        "--history",
    ]);
    assert!(
        stdout(&out).contains("ok: closure complete"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("history"), "{}", stdout(&out));

    let out = repo.ok(&["closure", "verify", "HEAD"]);
    assert!(
        stdout(&out).contains("ok: closure complete"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn closure_missing_or_corrupt_pack() {
    let repo = fixture_repo();
    let commit = head(&repo);
    repo.ok(&["closure", "export", "HEAD", "-o", "c.closure"]);
    let dir = repo.path().join("c.closure");
    let packs: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "pack"))
        .collect();
    assert!(!packs.is_empty());
    fs::remove_file(&packs[0]).unwrap();
    let out = repo.run(&["closure", "verify", &commit, "--from", "c.closure"]);
    assert_eq!(out.status.code(), Some(66));
    assert!(
        stderr(&out).contains("error:") || stdout(&out).contains("bad:"),
        "stdout={} stderr={}",
        stdout(&out),
        stderr(&out)
    );

    repo.ok(&["closure", "export", "HEAD", "-o", "c2.closure", "--force"]);
    let dir = repo.path().join("c2.closure");
    let pack = fs::read_dir(&dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "pack"))
        .unwrap();
    let mut bytes = fs::read(&pack).unwrap();
    let i = bytes.len() / 2;
    bytes[i] ^= 0xff;
    fs::write(&pack, bytes).unwrap();
    let out = repo.run(&["closure", "verify", &commit, "--from", "c2.closure"]);
    assert_eq!(out.status.code(), Some(65));
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        combined.contains("hash does not match") || combined.contains("bad:"),
        "{combined}"
    );
}

#[test]
fn closure_local_reports_missing_blob() {
    let repo = Repo::new();
    repo.commit_file("keep.txt", b"keep\n", "base");
    repo.commit_file("only-head.txt", b"unique-to-head\n", "head");
    let listing = stdout(&repo.ok(&["ls-tree", "-r", "HEAD"]));
    let blob_hex = listing
        .lines()
        .find(|l| l.contains("only-head.txt"))
        .and_then(|l| l.split_whitespace().nth(2))
        .expect("blob hex")
        .to_owned();
    let obj = repo
        .kit_dir()
        .join("objects")
        .join(&blob_hex[..2])
        .join(&blob_hex[2..]);
    fs::remove_file(&obj).unwrap();
    let out = repo.run(&["closure", "verify", "HEAD"]);
    assert_eq!(out.status.code(), Some(65), "stderr={}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("bad: closure incomplete"), "{text}");
    assert!(text.contains("missing"), "{text}");
    assert!(
        text.contains("note: unreferenced not checked (use --show-unreferenced)"),
        "{text}"
    );
}

#[test]
fn closure_local_reports_corrupt_blob() {
    let repo = Repo::new();
    repo.commit_file("keep.txt", b"keep\n", "base");
    repo.commit_file("only-head.txt", b"unique-to-head\n", "head");
    let listing = stdout(&repo.ok(&["ls-tree", "-r", "HEAD"]));
    let blob_hex = listing
        .lines()
        .find(|l| l.contains("only-head.txt"))
        .and_then(|l| l.split_whitespace().nth(2))
        .expect("blob hex")
        .to_owned();
    let obj = repo
        .kit_dir()
        .join("objects")
        .join(&blob_hex[..2])
        .join(&blob_hex[2..]);
    let mut bytes = fs::read(&obj).unwrap();
    let i = bytes.len() / 2;
    bytes[i] ^= 0xff;
    fs::write(&obj, bytes).unwrap();
    let out = repo.run(&["closure", "verify", "HEAD"]);
    assert_eq!(out.status.code(), Some(65), "stderr={}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("bad: closure incomplete: 0 missing, 1 corrupt"),
        "{text}"
    );
    assert!(
        text.contains("note: unreferenced not checked (use --show-unreferenced)"),
        "{text}"
    );
}

#[test]
fn closure_local_hides_unreferenced_unless_flag() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"first\n", "first");
    let first = head(&repo);
    repo.commit_file("b.txt", b"second\n", "second");

    let out = repo.ok(&["closure", "verify", &first]);
    let text = stdout(&out);
    assert!(text.contains("ok: closure complete"), "{text}");
    assert!(
        text.contains("note: unreferenced not checked (use --show-unreferenced)"),
        "{text}"
    );

    let out = repo.ok(&["closure", "verify", &first, "--format=json"]);
    let json = stdout(&out);
    assert!(json.contains("\"unreferenced_checked\":false"), "{json}");

    let out = repo.ok(&["closure", "verify", &first, "--show-unreferenced"]);
    let text = stdout(&out);
    assert!(text.contains("unreferenced"), "{text}");
    assert!(!text.contains("unreferenced not checked"), "{text}");

    let out = repo.ok(&[
        "closure",
        "verify",
        &first,
        "--show-unreferenced",
        "--format=json",
    ]);
    let json = stdout(&out);
    assert!(json.contains("\"unreferenced_checked\":true"), "{json}");
}

#[test]
fn closure_local_checks_the_trailer_of_an_unreferenced_pack() {
    let repo = fixture_repo();
    let layout = RepoLayout::single(repo.path());
    let pack = include_bytes!("../../../tests/golden/local_pack_mixed/mixed.pack");
    let index = include_bytes!("../../../tests/golden/local_pack_mixed/mixed.idx");
    let marker = include_bytes!("../../../tests/golden/local_pack_mixed/marker.bin");
    let key = kit_core::to_hex(&kit_core::pack_key(pack));
    let directory = layout.objects_dir().join("pack");
    fs::create_dir(&directory).unwrap();
    fs::write(layout.format_file(), marker).unwrap();
    let pack_path = directory.join(format!("{key}.pack"));
    fs::write(&pack_path, pack).unwrap();
    fs::write(directory.join(format!("{key}.idx")), index).unwrap();

    let args = ["closure", "verify", "HEAD", "--show-unreferenced"];
    assert!(stdout(&repo.ok(&args)).contains("ok: closure complete"));

    let mut corrupt = pack.to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&pack_path, corrupt).unwrap();
    repo.ok(&args[..3]);

    let out = repo.run(&args);
    assert_eq!(out.status.code(), Some(65), "stderr={}", stderr(&out));
    assert!(stderr(&out).contains("trailer"), "stderr={}", stderr(&out));
}

#[test]
fn closure_json_keys() {
    let repo = fixture_repo();
    let commit = head(&repo);
    let out = repo.ok(&[
        "closure",
        "export",
        "HEAD",
        "-o",
        "j.closure",
        "--format=json",
    ]);
    let js = stdout(&out);
    for key in ["root", "mode", "packs", "objects", "manifest"] {
        assert!(json_has(&js, key), "export json missing {key}: {js}");
    }
    let out = repo.ok(&[
        "closure",
        "verify",
        &commit,
        "--from",
        "j.closure",
        "--format=json",
    ]);
    let js = stdout(&out);
    for key in [
        "root",
        "mode",
        "verified",
        "complete",
        "missing",
        "corrupt",
        "unreferenced",
        "unreferenced_checked",
    ] {
        assert!(json_has(&js, key), "verify json missing {key}: {js}");
    }
}

#[test]
fn verify_proof_stdin_bundle_is_capped() {
    // A bundle piped via `-` that exceeds MAX_BUNDLE_BYTES must be rejected
    // with DATAERR without buffering the whole (attacker-controlled) stream
    // into memory first. Feed the cap plus one byte lazily via `io::repeat`
    // so the test never allocates or writes 64+ MiB itself.
    let repo = fixture_repo();
    let commit = head(&repo);

    let mut child = Command::new(env!("CARGO_BIN_EXE_kit"))
        .args(["verify-proof", &commit, "-"])
        .current_dir(repo.path())
        .env("XDG_CONFIG_HOME", repo.xdg())
        .env("HOME", repo.xdg())
        .env("EDITOR", "true")
        .env("VISUAL", "true")
        .env("GIT_EDITOR", "true")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kit");

    let mut stdin = child.stdin.take().expect("child stdin");
    let writer = std::thread::spawn(move || {
        let mut source = io::repeat(0).take(MAX_BUNDLE_BYTES as u64 + 1);
        // A broken pipe is expected once the child stops reading after the
        // cap is reached; that's fine, not a test failure.
        let _ = io::copy(&mut source, &mut stdin);
    });

    let start = Instant::now();
    let out = child.wait_with_output().expect("wait kit");
    writer.join().expect("writer thread panicked");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(20),
        "verify-proof took too long on an oversized stdin bundle: {elapsed:?}"
    );
    assert_eq!(
        out.status.code(),
        Some(65),
        "expected DATAERR, got status={:?} stderr={}",
        out.status.code(),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("exceeds") && stderr(&out).contains("byte cap"),
        "stderr should explain the cap: {}",
        stderr(&out)
    );
}
