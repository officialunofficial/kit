//! The git bridge: export, import, verification, state and patch series.
#![cfg(feature = "git-bridge")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::Command;

use kit_core::hash::{Hash, to_hex};
use kit_core::layout::{self, RepoLayout};
use kit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use kit_core::observer::Observer;
use kit_core::refs;
use kit_core::serialize;
use kit_core::sign::KeyPair;
use kit_core::store::ObjectStore;
use libkit::attest::{RepoKeySigner, Signer};
use libkit::git::export::{self, SignerFactory};
use libkit::git::import::{self, FetchRequest};
use libkit::git::verify::{self, ClaimBinding, claim_accepts};
use libkit::git::{Error, Event, patch, state, validate_url};
use libkit::git_bridge::gitobj::sha1_hex;
use libkit::git_bridge::map::{self, Direction};

/// Whether `git` runs. Without it a test has nothing to check. A run with
/// `KIT_TEST_STRICT` set must have it.
fn git_available() -> bool {
    if Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return true;
    }
    assert!(
        std::env::var_os("KIT_TEST_STRICT").is_none(),
        "git required (KIT_TEST_STRICT set) but not found"
    );
    eprintln!("SKIP: git not found");
    false
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Up Stream")
        .env("GIT_AUTHOR_EMAIL", "up@example.com")
        .env("GIT_COMMITTER_NAME", "Up Stream")
        .env("GIT_COMMITTER_EMAIL", "up@example.com")
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[derive(Default)]
struct Recorder(RefCell<Vec<Event>>);

impl Observer<Event> for Recorder {
    fn event(&self, event: &Event) {
        self.0.borrow_mut().push(event.clone());
    }
}

fn blob(store: &ObjectStore, data: &[u8]) -> Hash {
    let object = Object::Blob(Blob {
        data: data.to_vec(),
    });
    store
        .write(&serialize::serialize(&object).unwrap())
        .unwrap()
}

fn tree(store: &ObjectStore, files: &[(&str, Hash)]) -> Hash {
    let entries = files
        .iter()
        .map(|(name, object_hash)| TreeEntry {
            name: name.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: *object_hash,
        })
        .collect();
    store
        .write(&serialize::serialize(&Object::Tree(Tree { entries })).unwrap())
        .unwrap()
}

fn commit(
    store: &ObjectStore,
    tree: Hash,
    parents: Vec<Hash>,
    author: Identity,
    message: &str,
    time: u64,
) -> Hash {
    let commit = Commit::new_unannotated(
        tree,
        parents,
        author,
        [1; 32],
        message.as_bytes().to_vec(),
        time,
        [0; 64],
    );
    store
        .write(&serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap()
}

/// A repository whose `main` is a commit with `a.txt`.
fn kit_repo() -> (tempfile::TempDir, RepoLayout, Hash) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let a = blob(&store, b"one\n");
    let t = tree(&store, &[("a.txt", a)]);
    let head = commit(&store, t, vec![], Identity::ed25519([1; 32]), "first", 1);
    refs::write_ref(&layout, "main", &head).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    (dir, layout, head)
}

// ─── patch ──────────────────────────────────────────────────────────

/// The history `root <- one <- two`. `one` adds a line to `a.txt` and has an
/// opaque author and a line that looks like the start of a mail. `two` adds
/// `b.txt`.
struct Patches {
    dir: tempfile::TempDir,
    store: ObjectStore,
    layout: RepoLayout,
    root: Hash,
    two: Hash,
}

fn patches() -> Patches {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let one_line = blob(&store, b"one\n");
    let two_lines = blob(&store, b"one\ntwo\n");
    let b = blob(&store, b"new\n");
    let root_tree = tree(&store, &[("a.txt", one_line)]);
    let root = commit(
        &store,
        root_tree,
        vec![],
        Identity::ed25519([1; 32]),
        "root",
        1,
    );
    let one_tree = tree(&store, &[("a.txt", two_lines)]);
    let one = commit(
        &store,
        one_tree,
        vec![root],
        Identity::opaque(b"Ann <ann@example.com>".to_vec()),
        "Add two\n\nBody line\nFrom x Mon Sep 17 00:00:00 2001\n",
        1_700_000_000,
    );
    let two_tree = tree(&store, &[("a.txt", two_lines), ("b.txt", b)]);
    let two = commit(
        &store,
        two_tree,
        vec![one],
        Identity::ed25519([2; 32]),
        "Add b",
        1_700_000_100,
    );
    refs::write_ref(&layout, "main", &two).unwrap();
    refs::write_head_branch(&layout, "main").unwrap();
    Patches {
        dir,
        store,
        layout,
        root,
        two,
    }
}

#[test]
fn a_series_has_one_patch_for_each_commit_of_the_range() {
    let p = patches();
    let series = patch::series(p.dir.path(), &format!("{}..HEAD", to_hex(&p.root))).unwrap();
    assert_eq!(series.len(), 2);
    assert_eq!(series.skipped_merges(), 0);
    assert_eq!(series.start(), to_hex(&p.root));
    assert_eq!(series.end(), "HEAD");
    let all: Vec<patch::Patch> = series.patches().collect::<Result<_, _>>().unwrap();

    let first = &all[0];
    assert_eq!((first.number, first.total), (1, 2));
    assert_eq!(first.subject, "Add two");
    assert_eq!(first.from, "Ann <ann@example.com>");
    assert_eq!(first.date, "Tue, 14 Nov 2023 22:13:20 +0000");
    assert_eq!(
        first.body,
        ["Body line", ">From x Mon Sep 17 00:00:00 2001"],
        "a line that looks like a new mail is escaped"
    );
    assert_eq!(first.file_name(), "0001-Add-two.patch");
    assert_eq!(first.changes.len(), 1);
    assert_eq!(first.changes[0].entry.path, "a.txt");
    assert!(matches!(
        first.changes[0].body,
        libkit::diff::PatchBody::Hunks(_)
    ));

    let second = &all[1];
    assert_eq!(second.file_name(), "0002-Add-b.patch");
    assert!(second.from.ends_with(" <bridge@kit.invalid>"));
    assert!(second.body.is_empty());
    assert_eq!(second.changes[0].entry.path, "b.txt");
}

#[test]
fn a_series_leaves_out_a_merge_commit() {
    let p = patches();
    let side_blob = blob(&p.store, b"side\n");
    let side_tree = tree(&p.store, &[("c.txt", side_blob)]);
    let side = commit(
        &p.store,
        side_tree,
        vec![p.root],
        Identity::ed25519([3; 32]),
        "Side",
        1_700_000_050,
    );
    let merge_tree = tree(&p.store, &[("c.txt", side_blob)]);
    let merge = commit(
        &p.store,
        merge_tree,
        vec![p.two, side],
        Identity::ed25519([3; 32]),
        "Merge",
        1_700_000_200,
    );
    refs::write_ref(&p.layout, "main", &merge).unwrap();
    let series = patch::series(p.dir.path(), &format!("{}..HEAD", to_hex(&p.root))).unwrap();
    assert_eq!(series.len(), 3);
    assert_eq!(series.skipped_merges(), 1);
}

#[test]
fn an_empty_range_has_no_patch() {
    let p = patches();
    let series = patch::series(p.dir.path(), "HEAD..HEAD").unwrap();
    assert!(series.is_empty());
    assert_eq!(series.patches().count(), 0);
}

#[test]
fn a_range_end_that_is_not_a_commit_is_refused() {
    let p = patches();
    let t = tree(&p.store, &[]);
    let err = patch::series(p.dir.path(), &format!("{}..HEAD", to_hex(&t))).unwrap_err();
    assert!(
        matches!(err, Error::RangeNotACommit(ref spec) if *spec == to_hex(&t)),
        "{err:?}"
    );
    assert_eq!(err.to_string(), format!("{}: not a commit", to_hex(&t)));
}

#[test]
fn an_unknown_revision_names_itself() {
    let p = patches();
    let err = patch::series(p.dir.path(), "nope..HEAD").unwrap_err();
    assert!(err.to_string().starts_with("nope: "), "{err}");
}

#[test]
fn a_series_refuses_binary_content() {
    let p = patches();
    let bin = blob(&p.store, b"a\0b");
    let bin_tree = tree(&p.store, &[("bin", bin)]);
    let head = commit(
        &p.store,
        bin_tree,
        vec![p.two],
        Identity::ed25519([2; 32]),
        "Add bin",
        1_700_000_300,
    );
    refs::write_ref(&p.layout, "main", &head).unwrap();
    let series = patch::series(p.dir.path(), &format!("{}..HEAD", to_hex(&p.two))).unwrap();
    let err = series.patches().next().unwrap().unwrap_err();
    assert!(
        matches!(err, Error::BinaryChange { ref path, .. } if path == "bin"),
        "{err:?}"
    );
}

#[test]
fn a_series_needs_a_repository() {
    let dir = tempfile::tempdir().unwrap();
    let err = patch::series(dir.path(), "a..b").unwrap_err();
    assert!(matches!(err, Error::NotARepository), "{err:?}");
}

// ─── state ──────────────────────────────────────────────────────────

#[test]
fn state_lookup_skips_debris_and_asks_for_a_name_when_two_exist() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    ObjectStore::init(&layout).unwrap();
    let states = layout.git_state_dir();

    let err = state::resolve(&layout, None).unwrap_err();
    assert!(err.to_string().starts_with("no git bridge state"), "{err}");

    std::fs::create_dir_all(states.join("orig")).unwrap();
    // Debris of a `remote rename` that stopped half way.
    std::fs::create_dir_all(states.join(".rename.tmp.99999.0")).unwrap();
    let (name, path) = state::resolve(&layout, None).unwrap();
    assert_eq!((name.as_str(), path), ("orig", states.join("orig")));

    std::fs::create_dir_all(states.join("second")).unwrap();
    let err = state::resolve(&layout, None).unwrap_err();
    assert_eq!(
        err.to_string(),
        "multiple bridge states (orig, second); pick one with --remote-name"
    );
    assert!(state::resolve(&layout, Some("second")).is_ok());
    let err = state::resolve(&layout, Some("missing")).unwrap_err();
    assert_eq!(err.to_string(), "no bridge state for 'missing'");
    assert!(state::resolve(&layout, Some("a/b")).is_err());
}

#[test]
fn status_lists_each_state_with_its_bindings() {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    ObjectStore::init(&layout).unwrap();
    assert!(state::status(dir.path()).unwrap().is_empty());

    let up = layout.git_state_dir().join("up");
    std::fs::create_dir_all(&up).unwrap();
    map::bind_direction(&up, Direction::Import).unwrap();
    map::write_binding(&up, "source", "example.com/up").unwrap();
    map::bind_signer(&up, &[3; 32]).unwrap();
    std::fs::create_dir_all(layout.git_state_dir().join("bare")).unwrap();

    let states = state::status(dir.path()).unwrap();
    assert_eq!(states.len(), 2);
    assert_eq!(states[0].name, "bare");
    assert_eq!(states[0].direction, "unknown");
    assert_eq!(states[0].source, None);
    assert_eq!(states[1].name, "up");
    assert_eq!(states[1].direction, "import");
    assert_eq!(states[1].source.as_deref(), Some("example.com/up"));
    assert_eq!(states[1].importer_key.as_deref(), Some("0303030303030303"));
    assert!(!states[1].staging_present);
}

#[test]
fn a_stamp_longer_than_the_limit_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source");
    let limit = usize::try_from(state::MAX_STAMP_BYTES).unwrap();
    std::fs::write(&path, "x".repeat(limit)).unwrap();
    assert!(state::read_stamp(&path).is_ok());
    std::fs::write(&path, "x".repeat(limit + 1)).unwrap();
    assert!(state::read_stamp(&path).is_err());
}

// ─── locations and claims ───────────────────────────────────────────

#[test]
fn a_location_that_could_be_an_option_is_refused() {
    assert!(validate_url("https://example.com/up.git").is_ok());
    assert!(validate_url("/tmp/up").is_ok());
    let err = validate_url("").unwrap_err();
    assert_eq!(err.to_string(), "empty git URL or path");
    assert!(matches!(validate_url("  "), Err(Error::EmptyUrl)));
    let err = validate_url("--upload-pack=x").unwrap_err();
    assert_eq!(
        err.to_string(),
        "\"--upload-pack=x\" is not a valid git URL or path"
    );
}

#[test]
fn a_location_is_remote_by_the_rule_of_git() {
    for remote in [
        "https://example.com/up",
        "git@example.com:up.git",
        "host:up",
    ] {
        assert!(export::is_remote_location(remote), "{remote}");
    }
    for local in ["/tmp/up", "up", "./up", "C:/repo", "C:\\repo", "C:"] {
        assert!(!export::is_remote_location(local), "{local}");
    }
}

#[test]
fn a_claim_must_state_every_part_of_the_binding() {
    use libkit::attest::statement::{Statement, Subject, encode, sha256_hex};

    let twin = [7u8; 32];
    let git_id = [9u8; 20];
    let sha256 = sha256_hex(b"head");
    let binding = ClaimBinding {
        kit_ref: "refs/remotes/upstream/main",
        twin: &twin,
        sha256: &sha256,
        git_id: &git_id,
        source: "example.com/up",
    };
    let predicate = format!(
        "{{\"gitCommit\":\"{}\",\"refName\":\"{}\",\"remoteUrl\":\"{}\",\"schemaVersion\":1,\"specVersion\":{}}}",
        sha1_hex(&git_id),
        binding.kit_ref,
        binding.source,
        libkit::git_bridge::import::IMPORT_SPEC_VERSION
    );
    let statement = encode(&Statement {
        subjects: vec![Subject {
            name: Some(binding.kit_ref.to_owned()),
            digest_blake3_hex: to_hex(&twin),
            digest_sha256_hex: sha256.clone(),
        }],
        predicate_type: libkit::git::import::PREDICATE_TYPE.to_owned(),
        predicate_jcs: predicate.as_bytes(),
    })
    .unwrap();
    let payload = statement.as_bytes();

    assert!(claim_accepts(payload, &binding));
    assert!(!claim_accepts(b"", &binding));
    assert!(!claim_accepts(b"{}", &binding));
    assert!(!claim_accepts(
        payload,
        &ClaimBinding {
            kit_ref: "refs/remotes/upstream/other",
            ..binding
        }
    ));
    assert!(!claim_accepts(
        payload,
        &ClaimBinding {
            twin: &[8u8; 32],
            ..binding
        }
    ));
    assert!(!claim_accepts(
        payload,
        &ClaimBinding {
            sha256: "00",
            ..binding
        }
    ));
    assert!(!claim_accepts(
        payload,
        &ClaimBinding {
            git_id: &[1u8; 20],
            ..binding
        }
    ));
    assert!(!claim_accepts(
        payload,
        &ClaimBinding {
            source: "example.com/other",
            ..binding
        }
    ));
}

// ─── export ─────────────────────────────────────────────────────────

fn no_signer() -> impl FnMut() -> Result<Box<dyn Signer>, libkit::git::SignerError> {
    || Err("no signer".into())
}

fn request<'a>(dest: &'a str, remote_name: &'a str) -> export::Request<'a> {
    export::Request {
        dest,
        remote_name,
        refs: &[],
        attest: false,
        passthrough: false,
    }
}

#[test]
fn an_export_sends_the_branch_to_the_mirror() {
    if !git_available() {
        return;
    }
    let (_dir, layout, head) = kit_repo();
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror = mirror_dir.path().join("mirror");
    let dest = mirror.to_str().unwrap();
    let recorder = Recorder::default();

    let outcome = export::export(
        &layout,
        &request(dest, "mirror"),
        &mut no_signer(),
        &recorder,
    )
    .unwrap();
    assert!(outcome.skipped.is_empty());
    assert_eq!(outcome.exported.len(), 1);
    let exported = &outcome.exported[0];
    assert_eq!(exported.ref_name, "refs/heads/main");
    assert_eq!(exported.kit_hash, head);
    assert_eq!(
        git(&mirror, &["rev-parse", "refs/heads/main"]),
        sha1_hex(&exported.git_id)
    );
    assert!(recorder.0.borrow().is_empty());

    // The second run has the same result and keeps the lease.
    let again = export::export(
        &layout,
        &request(dest, "mirror"),
        &mut no_signer(),
        &recorder,
    )
    .unwrap();
    assert_eq!(again, outcome);

    // The state binds the remote name to the mirror.
    let other = mirror_dir.path().join("other");
    let err = export::export(
        &layout,
        &request(other.to_str().unwrap(), "mirror"),
        &mut no_signer(),
        &recorder,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::StateBound { ref name, .. } if name == "mirror"),
        "{err:?}"
    );
}

#[test]
fn an_export_mints_one_attestation_for_each_head() {
    if !git_available() {
        return;
    }
    let (_dir, layout, head) = kit_repo();
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror = mirror_dir.path().join("mirror");
    let mut signer: Box<SignerFactory<'_>> = Box::new(|| {
        let signer: Box<dyn Signer> = Box::new(RepoKeySigner::new(KeyPair::generate().unwrap()));
        Ok(signer)
    });
    let mut request = request(mirror.to_str().unwrap(), "mirror");
    request.attest = true;
    export::export(&layout, &request, &mut signer, &Recorder::default()).unwrap();
    git(&mirror, &["rev-parse", "refs/kit/attestations"]);
    assert_eq!(
        libkit::attest::store::list(&layout, &head).unwrap().len(),
        1
    );
}

#[test]
fn a_signer_that_cannot_be_built_stops_the_export() {
    if !git_available() {
        return;
    }
    let (_dir, layout, _head) = kit_repo();
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror = mirror_dir.path().join("mirror");
    let mut request = request(mirror.to_str().unwrap(), "mirror");
    request.attest = true;
    let err =
        export::export(&layout, &request, &mut no_signer(), &Recorder::default()).unwrap_err();
    assert!(matches!(err, Error::Signer(_)), "{err:?}");
    assert_eq!(err.to_string(), "no signer");
}

#[test]
fn an_export_refuses_what_it_cannot_send() {
    if !git_available() {
        return;
    }
    let (_dir, layout, _head) = kit_repo();
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror = mirror_dir.path().join("mirror");
    let dest = mirror.to_str().unwrap();
    let run = |request: &export::Request<'_>| {
        export::export(&layout, request, &mut no_signer(), &Recorder::default()).unwrap_err()
    };

    assert!(matches!(run(&request("", "mirror")), Error::EmptyUrl));
    assert!(matches!(
        run(&request("-x", "mirror")),
        Error::InvalidUrl(_)
    ));
    let bad_name = run(&request(dest, "bad/name"));
    assert!(
        bad_name.to_string().contains("bridge state name"),
        "{bad_name}"
    );

    let mut by_name = request(dest, "mirror");
    let short = ["main".to_owned()];
    by_name.refs = &short;
    let err = run(&by_name);
    assert_eq!(
        err.to_string(),
        "--ref main: expected refs/heads/... or refs/tags/..."
    );
    let missing = ["refs/heads/nope".to_owned()];
    by_name.refs = &missing;
    let err = run(&by_name);
    assert!(matches!(err, Error::RefNotFound(ref r) if r == "refs/heads/nope"));

    let mut passthrough = request(dest, "mirror");
    passthrough.passthrough = true;
    let err = run(&passthrough);
    assert!(
        matches!(err, Error::PassthroughNeedsImport { .. }),
        "{err:?}"
    );
}

#[test]
fn an_export_needs_a_branch_or_a_tag() {
    if !git_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror = mirror_dir.path().join("mirror");
    let err = export::export(
        &layout,
        &request(mirror.to_str().unwrap(), "mirror"),
        &mut no_signer(),
        &Recorder::default(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::NothingToExport), "{err:?}");
}

#[test]
fn a_ref_that_git_cannot_hold_is_skipped() {
    if !git_available() {
        return;
    }
    let (_dir, layout, head) = kit_repo();
    refs::write_ref(&layout, "topic.", &head).unwrap();
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror = mirror_dir.path().join("mirror");
    let recorder = Recorder::default();
    let outcome = export::export(
        &layout,
        &request(mirror.to_str().unwrap(), "mirror"),
        &mut no_signer(),
        &recorder,
    )
    .unwrap();
    assert_eq!(outcome.exported.len(), 1);
    assert_eq!(outcome.skipped.len(), 1);
    assert_eq!(outcome.skipped[0].ref_name, "refs/heads/topic.");
    assert!(matches!(
        recorder.0.borrow().as_slice(),
        [Event::RefSkipped { ref_name, .. }] if ref_name == "refs/heads/topic."
    ));

    // Only the refused ref: nothing goes out.
    let mut only = request(mirror.to_str().unwrap(), "mirror");
    let refused = ["refs/heads/topic.".to_owned()];
    only.refs = &refused;
    let err = export::export(&layout, &only, &mut no_signer(), &Recorder::default()).unwrap_err();
    assert!(
        matches!(err, Error::AllRefsSkipped { ref skipped } if skipped.len() == 1),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "every requested ref was skipped (1 refusals)"
    );
}

// ─── import, verify and fetch ───────────────────────────────────────

fn upstream(root: &Path) -> PathBuf {
    let up = root.join("up");
    std::fs::create_dir_all(&up).unwrap();
    git(&up, &["init", "--quiet", "--initial-branch=main", "."]);
    std::fs::write(up.join("a.txt"), "hello\n").unwrap();
    git(&up, &["add", "a.txt"]);
    git(&up, &["commit", "--quiet", "-m", "first"]);
    up
}

#[test]
fn an_import_checks_out_the_default_branch_and_verifies() {
    if !git_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let up = upstream(root.path());
    let fork = root.path().join("fork");
    let recorder = Recorder::default();
    let import_request = import::Request {
        url: up.to_str().unwrap(),
        remote_name: "upstream",
        key: None,
    };

    let summary = import::clone(&fork, &import_request, &recorder).unwrap();
    assert_eq!(summary.imported.len(), 1);
    assert_eq!(summary.imported[0].ref_name, "refs/heads/main");
    assert!(summary.skipped.is_empty());
    assert_eq!(summary.checked_out.as_deref(), Some("main"));
    assert_eq!(
        std::fs::read_to_string(fork.join("a.txt")).unwrap(),
        "hello\n"
    );
    assert!(
        recorder
            .0
            .borrow()
            .iter()
            .any(|e| matches!(e, Event::KeyGenerated { .. }))
    );

    let report = verify::verify(
        &fork,
        &verify::Request {
            remote_name: None,
            fork_audit: true,
            refs: &[],
        },
    )
    .unwrap();
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.verified.len(), 1);
    assert_eq!(report.verified[0].origin, "imported");
    assert!(report.imported > 0 && report.derived > 0);
    assert!(
        report.summary().ends_with("content-derived")
            || report.summary().contains("content-derived")
    );

    let states = state::status(&fork).unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].name, "upstream");
    assert_eq!(states[0].direction, "import");
    assert_eq!(states[0].tracking[0].0, "refs/heads/main");
    assert!(states[0].staging_present);

    let err = verify::verify(
        &fork,
        &verify::Request {
            remote_name: None,
            fork_audit: false,
            refs: &["refs/heads/other".to_owned()],
        },
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "refs/heads/other: not recorded in state 'upstream'"
    );
}

#[test]
fn a_fetch_pulls_the_new_commits_of_the_upstream() {
    if !git_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let up = upstream(root.path());
    let fork = root.path().join("fork");
    let import_request = import::Request {
        url: up.to_str().unwrap(),
        remote_name: "upstream",
        key: None,
    };
    import::clone(&fork, &import_request, &Recorder::default()).unwrap();
    let layout = layout::discover(&fork).unwrap();
    let fetch = FetchRequest {
        remote_name: "upstream",
        key: None,
    };

    // Nothing is new.
    let quiet = import::fetch(&layout, &fetch, true, &Recorder::default()).unwrap();
    assert_eq!(quiet.pulled, None);

    std::fs::write(up.join("b.txt"), "world\n").unwrap();
    git(&up, &["add", "b.txt"]);
    git(&up, &["commit", "--quiet", "-m", "second"]);
    let recorder = Recorder::default();
    let summary = import::fetch(&layout, &fetch, true, &recorder).unwrap();
    assert_eq!(summary.pulled.as_deref(), Some("main"));
    assert_eq!(
        std::fs::read_to_string(fork.join("b.txt")).unwrap(),
        "world\n"
    );
    assert!(
        recorder
            .0
            .borrow()
            .iter()
            .any(|e| matches!(e, Event::SigningKey { .. }))
    );
    let report = verify::verify(
        &fork,
        &verify::Request {
            remote_name: Some("upstream"),
            fork_audit: false,
            refs: &[],
        },
    )
    .unwrap();
    assert!(report.failures.is_empty(), "{:?}", report.failures);

    // A mirror toward the upstream would replace its history.
    let err = export::export(
        &layout,
        &request(up.to_str().unwrap(), "mirror"),
        &mut no_signer(),
        &Recorder::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::ImportSource { ref state, .. } if state == "upstream"),
        "{err:?}"
    );
}

#[test]
fn an_import_refuses_what_it_cannot_use() {
    if !git_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let up = upstream(root.path());
    let fork = root.path().join("fork");
    let url = up.to_str().unwrap();
    let import_request = import::Request {
        url,
        remote_name: "upstream",
        key: None,
    };
    import::clone(&fork, &import_request, &Recorder::default()).unwrap();

    let err = import::clone(&fork, &import_request, &Recorder::default()).unwrap_err();
    assert!(matches!(err, Error::DestinationExists(_)), "{err:?}");

    let option = import::Request {
        url: "-x",
        ..import_request
    };
    let target = root.path().join("never");
    let err = import::clone(&target, &option, &Recorder::default()).unwrap_err();
    assert!(matches!(err, Error::InvalidUrl(_)), "{err:?}");
    assert!(!target.exists(), "a refused location makes no directory");

    let layout = layout::discover(&fork).unwrap();
    let missing = FetchRequest {
        remote_name: "missing",
        key: None,
    };
    let err = import::fetch(&layout, &missing, false, &Recorder::default()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "no import state for 'missing' — run `kit git import <url>` first"
    );

    let other_name = import::Request {
        remote_name: "second",
        ..import_request
    };
    let err = import::import(&layout, &other_name, &Recorder::default()).unwrap_err();
    assert!(
        matches!(err, Error::DuplicateImport { ref other, .. } if other == "upstream"),
        "{err:?}"
    );
}

#[test]
fn an_attestation_of_a_local_import_names_no_path() {
    if !git_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let up = upstream(root.path());
    let fork = root.path().join("fork");
    let request = import::Request {
        url: up.to_str().unwrap(),
        remote_name: "upstream",
        key: None,
    };
    let summary = import::clone(&fork, &request, &Recorder::default()).unwrap();

    let layout = layout::discover(&fork).unwrap();
    let twin = summary.imported[0].kit_hash;
    let paths = libkit::attest::store::list(&layout, &twin).unwrap();
    assert_eq!(paths.len(), 1);
    let envelope = libkit::attest::store::load(&paths[0]).unwrap();
    let payload = String::from_utf8(envelope.payload).unwrap();
    assert!(payload.contains("\"remoteUrl\":\"local\""), "{payload}");
    assert!(!payload.contains(up.to_str().unwrap()), "{payload}");

    let report = verify::verify(
        &fork,
        &verify::Request {
            remote_name: None,
            fork_audit: false,
            refs: &[],
        },
    )
    .unwrap();
    assert!(report.failures.is_empty(), "{:?}", report.failures);
}

#[test]
fn a_claim_for_a_local_source_may_name_the_marker_or_the_path() {
    use libkit::attest::statement::{Statement, Subject, encode, sha256_hex};

    let twin = [7u8; 32];
    let git_id = [9u8; 20];
    let sha256 = sha256_hex(b"head");
    let binding = ClaimBinding {
        kit_ref: "refs/remotes/upstream/main",
        twin: &twin,
        sha256: &sha256,
        git_id: &git_id,
        source: "/srv/up",
    };
    let claim = |remote_url: &str| {
        let predicate = format!(
            "{{\"gitCommit\":\"{}\",\"refName\":\"{}\",\"remoteUrl\":\"{remote_url}\",\"schemaVersion\":1,\"specVersion\":{}}}",
            sha1_hex(&git_id),
            binding.kit_ref,
            libkit::git_bridge::import::IMPORT_SPEC_VERSION
        );
        encode(&Statement {
            subjects: vec![Subject {
                name: Some(binding.kit_ref.to_owned()),
                digest_blake3_hex: to_hex(&twin),
                digest_sha256_hex: sha256.clone(),
            }],
            predicate_type: libkit::git::import::PREDICATE_TYPE.to_owned(),
            predicate_jcs: predicate.as_bytes(),
        })
        .unwrap()
    };
    assert!(claim_accepts(claim("local").as_bytes(), &binding));
    // An attestation from an earlier import names the path itself.
    assert!(claim_accepts(claim("/srv/up").as_bytes(), &binding));
    assert!(!claim_accepts(claim("/srv/other").as_bytes(), &binding));

    let network = ClaimBinding {
        source: "https://example.com/up",
        ..binding
    };
    assert!(claim_accepts(
        claim("https://example.com/up").as_bytes(),
        &network
    ));
    assert!(!claim_accepts(claim("local").as_bytes(), &network));
}

#[test]
fn an_import_fetches_only_heads_and_tags() {
    if !git_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let up = upstream(root.path());
    git(&up, &["tag", "v1"]);
    let head = git(&up, &["rev-parse", "HEAD"]);
    git(&up, &["update-ref", "refs/replace/abc", &head]);
    git(&up, &["update-ref", "refs/notes/commits", &head]);
    git(&up, &["update-ref", "refs/pull/1/head", &head]);

    let fork = root.path().join("fork");
    let request = import::Request {
        url: up.to_str().unwrap(),
        remote_name: "upstream",
        key: None,
    };
    import::clone(&fork, &request, &Recorder::default()).unwrap();
    let layout = layout::discover(&fork).unwrap();
    let staging = map::state_dir(&layout, "upstream")
        .unwrap()
        .join("repo.git");
    let names = git(&staging, &["for-each-ref", "--format=%(refname)"]);
    assert_eq!(names, "refs/heads/main\nrefs/tags/v1");
}

#[test]
fn a_branch_whose_tip_is_not_a_commit_is_skipped() {
    if !git_available() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let up = upstream(root.path());
    let tree_id = git(&up, &["rev-parse", "HEAD^{tree}"]);
    // `update-ref` refuses a non-commit branch tip, so write the ref files.
    let heads = up.join(".git/refs/heads");
    std::fs::write(heads.join("tree-tip"), format!("{tree_id}\n")).unwrap();
    git(&up, &["tag", "-a", "-m", "to a tree", "tree-tag", &tree_id]);
    let tag_object = git(&up, &["rev-parse", "tree-tag"]);
    std::fs::write(heads.join("tag-of-tree"), format!("{tag_object}\n")).unwrap();
    let commit_id = git(&up, &["rev-parse", "HEAD"]);
    git(
        &up,
        &["tag", "-a", "-m", "to a commit", "commit-tag", &commit_id],
    );
    let commit_tag_object = git(&up, &["rev-parse", "commit-tag"]);
    std::fs::write(
        heads.join("tag-of-commit"),
        format!("{commit_tag_object}\n"),
    )
    .unwrap();

    let fork = root.path().join("fork");
    let request = import::Request {
        url: up.to_str().unwrap(),
        remote_name: "upstream",
        key: None,
    };
    let summary = import::clone(&fork, &request, &Recorder::default()).unwrap();

    let mut imported: Vec<&str> = summary
        .imported
        .iter()
        .map(|i| i.ref_name.as_str())
        .filter(|n| n.starts_with("refs/heads/"))
        .collect();
    imported.sort_unstable();
    assert_eq!(
        imported,
        ["refs/heads/main", "refs/heads/tag-of-commit"],
        "{summary:?}"
    );
    let mut skipped: Vec<&str> = summary
        .skipped
        .iter()
        .map(|s| s.ref_name.as_str())
        .collect();
    skipped.sort_unstable();
    assert_eq!(skipped, ["refs/heads/tag-of-tree", "refs/heads/tree-tip"]);
    let layout = layout::discover(&fork).unwrap();
    assert!(
        refs::read_remote_ref(&layout, "upstream", "tree-tip")
            .unwrap()
            .is_none()
    );
}
