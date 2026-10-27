//! Create attestations and verify them through the layout of a tree.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::cell::RefCell;
use std::path::Path;

use kit_core::hash::Hash;
use kit_core::layout::RepoLayout;
use kit_core::object::{Commit, Identity, Object};
use kit_core::observer::NoopObserver;
use kit_core::refs;
use kit_core::repo_lock;
use kit_core::serialize;
use kit_core::sign::KeyPair;
use kit_core::store::ObjectStore;
use libkit::attest::{Algorithm, Registry, TrustRoot};
use libkit::attestation::{self, Error, Failure, Request, SignerSpec};
use libkit::config::Config;
use libkit::lock;
use libkit::{Environment, Observer, attest_signer};

const SEED: [u8; 32] = [7; 32];
const OTHER_SEED: [u8; 32] = [9; 32];

fn commit(store: &ObjectStore, parents: Vec<Hash>, message: &[u8]) -> Hash {
    let commit = Commit::new_unannotated(
        [1; 32],
        parents,
        Identity::ed25519([1; 32]),
        [1; 32],
        message.to_vec(),
        0,
        [0; 64],
    );
    store
        .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

/// A repository on `main` with the history `root <- tip`.
fn repo() -> (tempfile::TempDir, RepoLayout, Hash, Hash) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let root = commit(&store, vec![], b"root");
    let tip = commit(&store, vec![root], b"tip");
    refs::write_ref(&layout, "main", &tip).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    (dir, layout, root, tip)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// Write a raw key file where the loader accepts it.
fn write_key(root: &Path, rel: &str, seed: &[u8; 32]) {
    let path = root.join(rel);
    let parent = path.parent().unwrap();
    std::fs::create_dir_all(parent).unwrap();
    set_mode(parent, 0o700);
    std::fs::write(&path, seed).unwrap();
    set_mode(&path, 0o600);
}

/// Make `registry` trust the Ed25519 repo key made from `seed`.
fn trust(registry: &mut Registry, seed: [u8; 32]) {
    let public = KeyPair::from_seed(seed).public.0;
    let keyid = format!(
        "blake3:{}",
        kit_core::hash::to_hex(&kit_core::hash::hash(&public))
    );
    registry.add(keyid, TrustRoot::Ed25519PubKey(public));
}

/// A registry that trusts the repo key made from `seed`.
fn trusting(seed: [u8; 32]) -> Registry {
    let mut registry = Registry::new();
    trust(&mut registry, seed);
    registry
}

fn create(
    layout: &RepoLayout,
    root: &Path,
    request: &Request,
) -> Result<attestation::Created, Error> {
    attestation::create(
        layout,
        &Environment::new(root),
        &Config::with_defaults(),
        request,
        &NoopObserver,
    )
}

#[derive(Default)]
struct Recorder(RefCell<Vec<lock::Event>>);

impl Observer<lock::Event> for Recorder {
    fn event(&self, event: &lock::Event) {
        self.0.borrow_mut().push(event.clone());
    }
}

#[test]
fn an_attestation_verifies_against_a_registry_that_trusts_its_key() {
    let (dir, layout, _root, tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let created = create(&layout, dir.path(), &Request::default()).unwrap();
    assert_eq!(created.signatures, 1);
    assert!(created.path.is_file());

    let checked = attestation::verify_commit(&layout, &tip, &trusting(SEED)).unwrap();
    assert_eq!(checked.len(), 1);
    assert_eq!(checked[0].id, Some(created.id));
    assert_eq!(checked[0].path, created.path);
    assert!(checked[0].is_verified(), "{:?}", checked[0].outcome);
}

#[test]
fn an_attestation_does_not_verify_against_a_registry_that_trusts_another_key() {
    let (dir, layout, _root, tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    create(&layout, dir.path(), &Request::default()).unwrap();

    let checked = attestation::verify_commit(&layout, &tip, &trusting(OTHER_SEED)).unwrap();
    assert_eq!(checked.len(), 1);
    assert!(!checked[0].is_verified());
    let result = checked[0].outcome.as_ref().unwrap();
    assert!(!result.any_verified);
    assert_eq!(result.signatures.len(), 1);
    assert!(!result.signatures[0].verified);
}

#[test]
fn a_commit_without_an_envelope_gives_an_empty_result() {
    let (_dir, layout, root, _tip) = repo();
    assert!(
        attestation::verify_commit(&layout, &root, &Registry::new())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_commit_defaults_to_head_and_a_given_commit_wins() {
    let (dir, layout, root, tip) = repo();
    assert_eq!(attestation::resolve_commit(&layout, None).unwrap(), tip);
    assert_eq!(
        attestation::resolve_commit(&layout, Some(root)).unwrap(),
        root
    );

    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let request = Request {
        commit: Some(root),
        ..Request::default()
    };
    create(&layout, dir.path(), &request).unwrap();
    let on_root = attestation::verify_commit(&layout, &root, &trusting(SEED)).unwrap();
    assert_eq!(on_root.len(), 1);
    let on_tip = attestation::verify_commit(&layout, &tip, &trusting(SEED)).unwrap();
    assert!(on_tip.is_empty());
}

#[test]
fn a_repository_without_a_head_commit_has_nothing_to_attest() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let err = create(&layout, dir.path(), &Request::default()).unwrap_err();
    assert!(matches!(err, Error::NoHeadCommit), "{err:?}");
    assert_eq!(err.to_string(), "HEAD has no commit yet");
}

#[test]
fn a_missing_commit_object_is_an_error() {
    let (dir, layout, _root, _tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let request = Request {
        commit: Some([5; 32]),
        ..Request::default()
    };
    let err = create(&layout, dir.path(), &request).unwrap_err();
    assert!(matches!(err, Error::ReadCommit { .. }), "{err:?}");
}

#[test]
fn a_missing_key_stops_the_run_before_anything_is_written() {
    let (dir, layout, _root, tip) = repo();
    let err = create(&layout, dir.path(), &Request::default()).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Signer(attest_signer::Error::MissingKeyFile { .. })
        ),
        "{err:?}"
    );
    assert!(!dir.path().join(".kit/keys/default.key").exists());
    assert!(
        attestation::verify_commit(&layout, &tip, &Registry::new())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_config_picks_the_signer_when_the_request_names_none() {
    let (dir, layout, _root, _tip) = repo();
    let mut config = Config::with_defaults();
    config.attest.default_algorithm = "rsa".into();
    let err = attestation::create(
        &layout,
        &Environment::new(dir.path()),
        &config,
        &Request::default(),
        &NoopObserver,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Signer(attest_signer::Error::UnknownAlgorithm(ref a)) if a == "rsa"),
        "{err:?}"
    );

    config.attest.default_algorithm = String::new();
    config.attest.signer = "sigstore".into();
    let err = attestation::create(
        &layout,
        &Environment::new(dir.path()),
        &config,
        &Request::default(),
        &NoopObserver,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Signer(attest_signer::Error::UnknownSignerKind(ref k)) if k == "sigstore"),
        "{err:?}"
    );
}

#[test]
fn a_second_signer_adds_a_second_signature_in_order() {
    let (dir, layout, _root, tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    write_key(dir.path(), ".kit/keys/second.key", &OTHER_SEED);
    let request = Request {
        algorithm: Some(Algorithm::Ed25519),
        signer: Some(attest_signer::Kind::RepoKey),
        additional: vec![
            "algorithm=ed25519,signer=repo-key,path=.kit/keys/second.key"
                .parse::<SignerSpec>()
                .unwrap(),
        ],
        ..Request::default()
    };
    let created = create(&layout, dir.path(), &request).unwrap();
    assert_eq!(created.signatures, 2);

    let mut registry = trusting(SEED);
    trust(&mut registry, OTHER_SEED);
    let checked = attestation::verify_commit(&layout, &tip, &registry).unwrap();
    let result = checked[0].outcome.as_ref().unwrap();
    assert_eq!(result.signatures.len(), 2);
    assert!(result.signatures.iter().all(|s| s.verified));
}

#[test]
fn an_additional_key_path_with_a_parent_component_is_refused() {
    let (dir, layout, _root, tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let request = Request {
        additional: vec![
            "algorithm=ed25519,signer=repo-key,path=../outside.key"
                .parse::<SignerSpec>()
                .unwrap(),
        ],
        ..Request::default()
    };
    let err = create(&layout, dir.path(), &request).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Signer(attest_signer::Error::InvalidKeyFile { .. })
        ),
        "{err:?}"
    );
    assert!(
        attestation::verify_commit(&layout, &tip, &Registry::new())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_predicate_file_sets_the_statement_predicate() {
    let (dir, layout, _root, tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let predicate = dir.path().join("predicate.json");
    std::fs::write(&predicate, br#"{"built":"yes"}"#).unwrap();
    let request = Request {
        predicate_type: Some("https://example.com/p/v1".to_owned()),
        predicate_file: Some(predicate),
        ..Request::default()
    };
    let created = create(&layout, dir.path(), &request).unwrap();
    let text = std::fs::read_to_string(&created.path).unwrap();
    assert!(text.contains("payload"));
    assert!(attestation::verify_commit(&layout, &tip, &trusting(SEED)).unwrap()[0].is_verified());
}

#[test]
fn a_predicate_that_is_not_an_object_is_refused() {
    let (dir, layout, _root, _tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let predicate = dir.path().join("predicate.json");
    for body in [&b"[1]"[..], b"not json", b"\"text\""] {
        std::fs::write(&predicate, body).unwrap();
        let request = Request {
            predicate_file: Some(predicate.clone()),
            ..Request::default()
        };
        let err = create(&layout, dir.path(), &request).unwrap_err();
        assert!(
            matches!(err, Error::PredicateNotObject),
            "{body:?}: {err:?}"
        );
    }
}

#[test]
fn a_predicate_file_over_the_cap_is_refused_and_a_missing_one_is_an_input_error() {
    let (dir, layout, _root, _tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let predicate = dir.path().join("predicate.json");
    let size = usize::try_from(attestation::MAX_PREDICATE_BYTES).unwrap() + 1;
    std::fs::write(&predicate, vec![b' '; size]).unwrap();
    let request = Request {
        predicate_file: Some(predicate),
        ..Request::default()
    };
    let err = create(&layout, dir.path(), &request).unwrap_err();
    assert!(matches!(err, Error::PredicateTooLarge(_)), "{err:?}");

    let request = Request {
        predicate_file: Some(dir.path().join("absent.json")),
        ..Request::default()
    };
    let err = create(&layout, dir.path(), &request).unwrap_err();
    assert!(matches!(err, Error::PredicateRead { .. }), "{err:?}");
}

#[test]
fn a_live_server_is_reported_to_the_observer_during_a_write() {
    let (dir, layout, _root, _tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let _serving = repo_lock::acquire_shared(
        layout.common_dir(),
        lock::SERVE_LOCK,
        std::time::Duration::from_millis(200),
    )
    .unwrap();
    let recorder = Recorder::default();
    attestation::create(
        &layout,
        &Environment::new(dir.path()),
        &Config::with_defaults(),
        &Request::default(),
        &recorder,
    )
    .unwrap();
    assert_eq!(
        *recorder.0.borrow(),
        vec![lock::Event::RepositoryServed {
            worktree_root: layout.worktree_root().to_path_buf()
        }]
    );
}

/// The directory that holds the envelopes of `commit`.
fn envelope_dir(layout: &RepoLayout, commit: &Hash) -> std::path::PathBuf {
    layout
        .attestations_dir()
        .join(kit_core::hash::to_hex(commit))
}

/// A file name that the attestation store lists: the hex of an id, then
/// the extension.
fn listed_name(id: u8) -> String {
    format!("{}.dsse", kit_core::hash::to_hex(&[id; 32]))
}

#[test]
fn a_damaged_envelope_is_reported_and_the_others_still_run() {
    let (dir, layout, _root, tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let created = create(&layout, dir.path(), &Request::default()).unwrap();
    let bad = envelope_dir(&layout, &tip).join(listed_name(3));
    std::fs::write(&bad, b"not an envelope").unwrap();

    let checked = attestation::verify_commit(&layout, &tip, &trusting(SEED)).unwrap();
    assert_eq!(checked.len(), 2);
    let junk = checked.iter().find(|c| c.path == bad).unwrap();
    assert!(matches!(junk.outcome, Err(Failure::Malformed(_))));
    assert!(junk.id.is_some());
    assert!(!junk.is_verified());
    assert!(
        junk.outcome
            .as_ref()
            .unwrap_err()
            .to_string()
            .starts_with("malformed envelope: ")
    );
    let good = checked.iter().find(|c| c.path == created.path).unwrap();
    assert!(good.is_verified());
}

#[test]
fn an_envelope_over_the_size_limit_is_a_read_failure() {
    let (dir, layout, _root, tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    create(&layout, dir.path(), &Request::default()).unwrap();
    let big = envelope_dir(&layout, &tip).join(listed_name(4));
    let size = kit_attest_max_envelope() + 1;
    std::fs::write(&big, vec![0u8; size]).unwrap();

    let checked = attestation::verify_commit(&layout, &tip, &trusting(SEED)).unwrap();
    let big = checked.iter().find(|c| c.path == big).unwrap();
    assert!(matches!(big.outcome, Err(Failure::Read(_))));
    assert!(big.id.is_none());
}

fn kit_attest_max_envelope() -> usize {
    libkit::attest::store::MAX_ENVELOPE_SIZE
}

#[test]
fn an_envelope_stored_under_another_commit_is_a_subject_mismatch() {
    let (dir, layout, root, tip) = repo();
    write_key(dir.path(), ".kit/keys/default.key", &SEED);
    let created = create(&layout, dir.path(), &Request::default()).unwrap();
    std::fs::create_dir_all(envelope_dir(&layout, &root)).unwrap();
    let replayed = envelope_dir(&layout, &root).join(created.path.file_name().unwrap());
    std::fs::copy(&created.path, &replayed).unwrap();

    let checked = attestation::verify_commit(&layout, &root, &trusting(SEED)).unwrap();
    assert_eq!(checked.len(), 1);
    match &checked[0].outcome {
        Err(Failure::SubjectMismatch {
            statement,
            requested,
        }) => {
            assert_eq!(statement, &tip);
            assert_eq!(requested, &root);
        }
        other => panic!("{other:?}"),
    }
    assert!(!checked[0].is_verified());
}
