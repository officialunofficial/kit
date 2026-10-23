//! The captured ssh sessions (`rust/tests/golden/ssh-serve/`). Each input
//! file is a script of frames. Each output file is what the server wrote,
//! byte for byte, with the version in the only frame that names it.
//!
//! Sessions 1 and 2 ran against a repository with open writes. Session 3
//! ran against a repository that only its owner may write, as a session
//! without the owner key.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use common::*;
use mkit_core::hash::{Hash, hash};
use mkit_core::protocol::{PackKey, Transport as _};
use mkit_core::refs::RefWriteCondition;
use mkit_rpc::mkit::common::v1::RefExpectation;
use mkit_rpc::mkit::rpc::v1::ssh::SshFrame;
use mkit_serve::{ReadFrames, SessionConfig, SessionEnd, WriteFrames, WritePolicy, serve_session};
use mkit_transport_file::FileTransport;

const SESSION_1_IN: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-1.in.bin");
const SESSION_1_OUT: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-1.bin");
const SESSION_2_IN: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-2.in.bin");
const SESSION_2_OUT: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-2.bin");
const SESSION_3_IN: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-3.in.bin");
const SESSION_3_OUT: &[u8] = include_bytes!("../../../tests/golden/ssh-serve/session-3.bin");

fn encode(bodies: Vec<Option<Body>>) -> Vec<u8> {
    let mut input = Vec::new();
    for body in bodies {
        mkit_rpc::write_frame(&mut input, &frame(body)).unwrap();
    }
    input
}

/// Replay `input` as the session of `key` and return the bytes written.
fn replay(fx: &Fixture, key: Option<[u8; 32]>, input: &[u8]) -> Vec<u8> {
    let mut src = ReadFrames(std::io::Cursor::new(input.to_vec()));
    let mut sink = WriteFrames(Vec::new());
    let cfg = SessionConfig::new(SERVER_ID);
    let end = serve_session(&fx.repo, key, &mut src, &mut sink, &cfg);
    assert_eq!(end, SessionEnd::Clean);
    sink.0
}

/// Frame by frame, for a readable failure before the byte comparison.
fn assert_same(got: &[u8], want: &[u8]) {
    let decode = |bytes: &[u8]| {
        let mut r = std::io::Cursor::new(bytes);
        let mut out = Vec::new();
        while r.position() < bytes.len() as u64 {
            out.push(mkit_rpc::read_frame::<_, SshFrame>(&mut r).unwrap());
        }
        out
    };
    let (got_frames, want_frames) = (decode(got), decode(want));
    for (i, (g, w)) in got_frames.iter().zip(&want_frames).enumerate() {
        assert_eq!(g, w, "frame {i}");
    }
    assert_eq!(got_frames.len(), want_frames.len(), "frame count");
    assert_eq!(got, want);
}

/// The script of session 1, and the state it runs against: the refs `main`,
/// `dev` and `tags/v1`, and one 1000-byte pack.
#[allow(clippy::too_many_lines)]
fn session_1() -> (Vec<u8>, Vec<(&'static str, Hash)>, Vec<u8>) {
    let seeded = pack_bytes(1000, 7);
    let seeded_id = hash(&seeded);
    let fresh = pack_bytes(3000, 9);
    let fresh_id = hash(&fresh);
    let empty_id = hash(b"");
    let bogus = pack_bytes(40, 1);
    let bodies = vec![
        hello(),
        list_refs(Some("refs/heads/")),
        list_refs(None),
        list_refs(Some("/bad")),
        read_ref("refs/heads/main"),
        read_ref("refs/heads/absent"),
        read_ref("refs/heads/.hidden"),
        exists(&seeded_id),
        exists(&[0x99; 32]),
        exists(&[0x99; 16]),
        update(
            "refs/heads/main",
            &[0x44; 32],
            Some(RefExpectation::Match),
            Some(&[0x11; 32]),
        ),
        update(
            "refs/heads/main",
            &[0x55; 32],
            Some(RefExpectation::Match),
            Some(&[0x11; 32]),
        ),
        update(
            "refs/heads/ghost",
            &[0x55; 32],
            Some(RefExpectation::Match),
            Some(&[0x66; 32]),
        ),
        update(
            "refs/heads/dev",
            &[0x55; 32],
            Some(RefExpectation::Missing),
            None,
        ),
        update(
            "refs/heads/main",
            &[0x55; 5],
            Some(RefExpectation::Any),
            None,
        ),
        update("refs/heads/main", &[0x55; 32], None, None),
        update(
            "refs/heads/main",
            &[0x55; 32],
            Some(RefExpectation::Match),
            None,
        ),
        update(
            "refs/heads/any",
            &[0x77; 32],
            Some(RefExpectation::Any),
            Some(&[0x01; 32]),
        ),
        update(
            "refs/heads/.hidden",
            &[0x77; 32],
            Some(RefExpectation::Any),
            None,
        ),
        download(Some(&seeded_id)),
        download(Some(&[0x99; 32])),
        download(None),
        // A valid two-chunk upload.
        upload_header(&fresh_id, Some(fresh.len() as u64)),
        chunk(&fresh_id, Some(0), &fresh[..1200], false),
        chunk(&fresh_id, Some(1200), &fresh[1200..], true),
        // The empty pack: one empty `last` chunk each way.
        upload_header(&empty_id, Some(0)),
        chunk(&empty_id, Some(0), &[], true),
        download(Some(&empty_id)),
        // Header errors: nothing is read after them.
        upload_header(&fresh_id, None),
        upload_header(&[0x01; 7], Some(3)),
        // Bytes that do not hash to the declared id.
        upload_header(&[0x77; 32], Some(bogus.len() as u64)),
        chunk(&[0x77; 32], Some(0), &bogus, true),
        // An offset gap.
        upload_header(&fresh_id, Some(fresh.len() as u64)),
        chunk(&fresh_id, Some(5), &fresh, true),
        // A frame that is not a chunk inside an upload: the upload consumes it.
        upload_header(&fresh_id, Some(fresh.len() as u64)),
        read_ref("refs/heads/main"),
        // Stray and misplaced frames.
        chunk(&fresh_id, Some(0), &fresh[..10], false),
        hello(),
        None,
        Some(Body::HelloResponse(Box::default())),
        list_refs(Some("refs/")),
        exists(&fresh_id),
        download(Some(&fresh_id)),
        close(),
        // Never read: the session ended at Close.
        read_ref("refs/heads/main"),
    ];
    let refs = vec![
        ("refs/heads/main", [0x11; 32]),
        ("refs/heads/dev", [0x22; 32]),
        ("refs/tags/v1", [0x33; 32]),
    ];
    (encode(bodies), refs, seeded)
}

#[test]
fn session_1_matches_the_capture() {
    let (input, refs, seeded) = session_1();
    assert_eq!(
        input, SESSION_1_IN,
        "the builder must produce the captured script"
    );
    let fx = Fixture::new();
    fx.seed(&refs, &[&seeded]);
    assert_same(&replay(&fx, None, &input), SESSION_1_OUT);
    // The files are the ones `FileTransport` reads.
    let tx = FileTransport::new(fx.root());
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some([0x44; 32]));
    assert_eq!(tx.read_ref("refs/heads/any").unwrap(), Some([0x77; 32]));
}

/// The script of session 2: `ListRefs` prefixes at and off path-component
/// boundaries (SPEC-REFS §4), then a download of a pack over one 800 KiB
/// chunk. The state: the refs `main`, `feat/x`, `featx` and `tags/v1`, one
/// pack, and a stray file `refs/heads/README` that every listing skips.
///
/// The exact name of a ref (`refs/heads/main`) is not a prefix of this
/// script: SPEC-REFS §4 says a listing skips a ref named exactly the prefix.
#[test]
fn session_2_matches_the_capture() {
    let big = pack_bytes(800 * 1024 + 1000, 5);
    let big_id = hash(&big);
    let prefixes = [
        None,
        Some(""),
        Some("refs/heads"),
        Some("refs/heads/"),
        Some("refs/heads//"),
        Some("refs/heads/feat"),
        Some("refs/heads/feat/"),
        Some("refs/heads/ma"),
        Some("refs"),
        Some("refs/"),
        Some("refs//"),
        Some("refs/tags"),
        Some("nope/"),
    ];
    let mut bodies = vec![hello()];
    bodies.extend(prefixes.map(list_refs));
    bodies.extend([download(Some(&big_id)), exists(&big_id), close()]);
    let input = encode(bodies);
    assert_eq!(
        input, SESSION_2_IN,
        "the builder must produce the captured script"
    );

    let fx = Fixture::new();
    let tx = FileTransport::new(fx.root());
    for (name, id) in [
        ("refs/heads/main", [0x11; 32]),
        ("refs/heads/feat/x", [0x12; 32]),
        ("refs/heads/featx", [0x13; 32]),
        ("refs/tags/v1", [0x33; 32]),
    ] {
        tx.update_ref(name, RefWriteCondition::Any, &id).unwrap();
    }
    tx.upload_pack(&big, &PackKey::new(big_id)).unwrap();
    std::fs::write(fx.root().join("refs/heads/README"), b"not a ref\n").unwrap();
    assert_same(&replay(&fx, None, &input), SESSION_2_OUT);
}

const OWNER: [u8; 32] = [0x0a; 32];
const OTHER: [u8; 32] = [0x0b; 32];
const BRANCH: &str = "refs/heads/main";

/// Session 3 runs against a repository that only its owner may write, as a
/// session with another key. The upload and the CAS-correct ref write get
/// `INVALID_REQUEST "write not permitted"`. The read still answers. The
/// seeded ref does not move.
#[test]
fn session_3_refuses_a_session_that_is_not_the_owner() {
    let ref_id = [0x44; 32];
    let pack = pack_bytes(64, 3);
    let pack_id = hash(&pack);
    let input = encode(vec![
        hello(),
        upload_header(&pack_id, Some(pack.len() as u64)),
        chunk(&pack_id, Some(0), &pack, true),
        update(
            BRANCH,
            &[0x55; 32],
            Some(RefExpectation::Match),
            Some(&ref_id),
        ),
        read_ref(BRANCH),
        close(),
    ]);
    assert_eq!(
        input, SESSION_3_IN,
        "the builder must produce the captured script"
    );

    let fx = Fixture::with_policy(WritePolicy::OwnedBy(OWNER));
    // The owner seeds the ref. The replay must not move it.
    let (end, frames) = fx.run_as(
        Some(OWNER),
        [update(BRANCH, &ref_id, Some(RefExpectation::Any), None)],
    );
    assert_eq!(end, SessionEnd::Clean, "seeding failed: {frames:?}");
    assert!(matches!(frames[0].body, Some(Body::UpdateRefResponse(_))));

    assert_same(&replay(&fx, Some(OTHER), &input), SESSION_3_OUT);
    assert_eq!(
        FileTransport::new(fx.root()).read_ref(BRANCH).unwrap(),
        Some(ref_id)
    );
    assert!(!fx.pack_present(pack_id));
}

#[test]
fn the_write_policy_decides_each_write() {
    let (bytes, id) = valid_pack();
    let write = |fx: &Fixture, key| {
        fx.run_as(
            key,
            [
                update(BRANCH, &[1; 32], Some(RefExpectation::Any), None),
                upload_header(&id, Some(bytes.len() as u64)),
                chunk(&id, Some(0), &bytes, true),
                read_ref(BRANCH),
            ],
        )
        .1
    };
    let denied = |f: &SshFrame| {
        assert_error(
            f,
            mkit_rpc::mkit::rpc::v1::ErrorCode::InvalidRequest,
            "write not permitted",
        );
    };

    // Owner policy: only the owner key writes. No key does not.
    let fx = Fixture::with_policy(WritePolicy::OwnedBy(OWNER));
    let frames = write(&fx, None);
    denied(&frames[0]);
    denied(&frames[1]);
    assert!(!fx.pack_present(id));
    let frames = write(&fx, Some(OWNER));
    assert!(matches!(frames[0].body, Some(Body::UpdateRefResponse(_))));
    assert!(matches!(frames[1].body, Some(Body::UploadPackResponse(_))));
    assert!(fx.pack_present(id));

    // Read-only policy: not even the owner key writes, and reads answer.
    let fx = Fixture::with_policy(WritePolicy::ReadOnly);
    let frames = write(&fx, Some(OWNER));
    denied(&frames[0]);
    denied(&frames[1]);
    assert!(matches!(frames[2].body, Some(Body::ReadRefResponse(_))));

    // Open policy: any session writes.
    let fx = Fixture::new();
    let frames = write(&fx, None);
    assert!(matches!(frames[0].body, Some(Body::UpdateRefResponse(_))));
    assert!(matches!(frames[1].body, Some(Body::UploadPackResponse(_))));
}

/// A refused upload still reads the whole stream, so a framing error in it
/// gets its own reply, not the refusal.
#[test]
fn a_refused_upload_still_checks_its_framing() {
    let fx = Fixture::with_policy(WritePolicy::ReadOnly);
    let (bytes, id) = valid_pack();
    let (_, frames) = fx.run([
        upload_header(&id, Some(bytes.len() as u64)),
        chunk(&id, Some(3), &bytes, true),
        exists(&id),
    ]);
    assert_error(
        &frames[0],
        mkit_rpc::mkit::rpc::v1::ErrorCode::InvalidRequest,
        "PackChunk.offset is not the expected next offset",
    );
    assert!(matches!(frames[1].body, Some(Body::PackExistsResponse(_))));
}
