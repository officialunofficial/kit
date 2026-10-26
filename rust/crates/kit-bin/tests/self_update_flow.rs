//! End-to-end `kit self update` flow against a mock release origin.
//!
//! Exercises the injectable core (`run_update` + `UpdateEnv`) with a
//! mockito server standing in for the GitHub releases API and a
//! tempdir standing in for the install dir. The "binaries" are shell
//! scripts that honor the `kit version` output contract, which is
//! all the pre-swap self-check needs. The `cosign` program is a stub
//! script that accepts or rejects the archive.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::{Path, PathBuf};

use kit_bin::commands::self_update::{Opts, Outcome, UpdateEnv, run_update};
use kit_core::hash;

const TEST_TARGET: &str = "x-test-triple";

// ------------------------------------------------------------- fixtures

struct Install {
    _dir: tempfile::TempDir,
    /// A stub `cosign` that accepts every archive.
    cosign_ok: PathBuf,
    /// A stub `cosign` that rejects every archive.
    cosign_bad: PathBuf,
    exe: PathBuf,
    bin_dir: PathBuf,
    state_dir: PathBuf,
}

/// A managed install: fake binary + both installer receipts.
fn managed_install(tag: &str) -> Install {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let exe = bin_dir.join("kit");
    std::fs::write(&exe, script_binary(tag.trim_start_matches('v'))).unwrap();
    std::fs::write(bin_dir.join(".kit-installed-tag"), format!("{tag}\n")).unwrap();
    std::fs::write(state_dir.join("installed-tag"), format!("{tag}\n")).unwrap();
    let cosign_ok = stub_cosign(dir.path(), "cosign-ok", 0);
    let cosign_bad = stub_cosign(dir.path(), "cosign-bad", 1);
    Install {
        _dir: dir,
        cosign_ok,
        cosign_bad,
        exe,
        bin_dir,
        state_dir,
    }
}

/// A stub `cosign` that records its arguments and exits with `code`.
fn stub_cosign(dir: &Path, name: &str, code: i32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    let args = dir.join(format!("{name}.args"));
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho 'bad signature' >&2\nexit {code}\n",
            args.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A fake kit binary honoring the byte-exact `version` contract.
fn script_binary(bare: &str) -> Vec<u8> {
    format!("#!/bin/sh\nif [ \"$1\" = version ]; then printf 'kit {bare}\\n'; fi\n").into_bytes()
}

/// A fake kit binary that also leaves a marker file when it runs.
fn marker_binary(bare: &str, marker: &Path) -> Vec<u8> {
    format!(
        "#!/bin/sh\ntouch '{}'\nif [ \"$1\" = version ]; then printf 'kit {bare}\\n'; fi\n",
        marker.display()
    )
    .into_bytes()
}

fn tgz_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    for (path, body) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o755);
        h.set_cksum();
        builder.append_data(&mut h, path, *body).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// Stand up a mock origin serving `latest` → `tag` plus the tag's
/// release JSON and its assets. Returns the guard (mocks live as long
/// as it does).
struct Origin {
    server: mockito::ServerGuard,
}

fn origin_with_release(tag: &str, archive: &[u8]) -> Origin {
    origin_with_assets(tag, archive, None, true, true)
}

fn origin_with_release_and_sha256_body(
    tag: &str,
    archive: &[u8],
    sha256_override: Option<&[u8]>,
) -> Origin {
    origin_with_assets(tag, archive, sha256_override, true, true)
}

/// `sha256_override` lets the tamper test serve a sidecar that does
/// not match the served archive.
fn origin_with_assets(
    tag: &str,
    archive: &[u8],
    sha256_override: Option<&[u8]>,
    with_sha256: bool,
    with_bundle: bool,
) -> Origin {
    use sha2::Digest as _;
    let bare = tag.trim_start_matches('v');
    let archive_name = format!("kit-{bare}-{TEST_TARGET}.tar.gz");
    let sha_body = format!(
        "{}  {archive_name}\n",
        hash::to_hex_bytes(&sha2::Sha256::digest(archive))
    );
    let sha_body = sha256_override.map_or_else(|| sha_body.clone().into_bytes(), <[u8]>::to_vec);

    let mut server = mockito::Server::new();
    let url = server.url();
    let mut assets = vec![format!(
        r#"{{"name":"{archive_name}","url":"{url}/assets/archive"}}"#
    )];
    if with_sha256 {
        assets.push(format!(
            r#"{{"name":"{archive_name}.sha256","url":"{url}/assets/sha256"}}"#
        ));
    }
    if with_bundle {
        assets.push(format!(
            r#"{{"name":"{archive_name}.cosign.bundle","url":"{url}/assets/bundle"}}"#
        ));
    }
    let release_json = format!(r#"{{"tag_name":"{tag}","assets":[{}]}}"#, assets.join(","));
    server
        .mock("GET", "/releases/latest")
        .with_body(&release_json)
        .create();
    server
        .mock("GET", format!("/releases/tags/{tag}").as_str())
        .with_body(&release_json)
        .create();
    server
        .mock("GET", "/assets/archive")
        .with_body(archive)
        .create();
    server
        .mock("GET", "/assets/sha256")
        .with_body(&sha_body)
        .create();
    server
        .mock("GET", "/assets/bundle")
        .with_body("{}")
        .create();
    Origin { server }
}

fn env_for(origin: &Origin, install: &Install, current: &str) -> UpdateEnv {
    UpdateEnv {
        api_base: origin.server.url(),
        token: None,
        exe_path: install.exe.clone(),
        state_dir: install.state_dir.clone(),
        current_version: current.to_owned(),
        target: TEST_TARGET.to_owned(),
        allow_loopback_http: true,
        cosign: install.cosign_ok.clone(),
    }
}

fn opts() -> Opts {
    Opts {
        version: None,
        check: false,
        allow_downgrade: false,
        format: "human".to_owned(),
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

// ----------------------------------------------------------------- tests

#[test]
fn full_update_swaps_binary_and_receipts() {
    let new_binary = script_binary("9.9.9");
    let archive = tgz_with(&[
        (
            &format!("kit-9.9.9-{TEST_TARGET}/README.md"),
            b"readme".as_slice(),
        ),
        (
            &format!("kit-9.9.9-{TEST_TARGET}/kit"),
            new_binary.as_slice(),
        ),
    ]);
    let origin = origin_with_release("v9.9.9", &archive);
    let install = managed_install("v0.3.0");

    let outcome = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap();
    assert_eq!(
        outcome,
        Outcome::Updated {
            from: "v0.3.0".to_owned(),
            to: "v9.9.9".to_owned(),
            exe: install.exe.clone(),
        }
    );
    assert_eq!(std::fs::read(&install.exe).unwrap(), new_binary);
    assert_eq!(
        read(&install.bin_dir.join(".kit-installed-tag")),
        "v9.9.9\n"
    );
    assert_eq!(read(&install.state_dir.join("installed-tag")), "v9.9.9\n");
    // Same-dir staging file cleaned up by the rename.
    let stray: Vec<_> = std::fs::read_dir(&install.bin_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".kit-self-update.")
        })
        .collect();
    assert!(stray.is_empty(), "staging file left behind: {stray:?}");
}

#[test]
fn up_to_date_is_a_no_op() {
    let archive = tgz_with(&[(&format!("kit-0.3.0-{TEST_TARGET}/kit"), b"x".as_slice())]);
    let origin = origin_with_release("v0.3.0", &archive);
    let install = managed_install("v0.3.0");
    let before = std::fs::read(&install.exe).unwrap();

    let outcome = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap();
    assert_eq!(
        outcome,
        Outcome::UpToDate {
            current: "v0.3.0".to_owned()
        }
    );
    assert_eq!(std::fs::read(&install.exe).unwrap(), before);
}

#[test]
fn latest_downgrade_refused() {
    let archive = tgz_with(&[(&format!("kit-0.2.0-{TEST_TARGET}/kit"), b"x".as_slice())]);
    let origin = origin_with_release("v0.2.0", &archive);
    let install = managed_install("v0.3.0");

    let (msg, _) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("silently downgrade"), "{msg}");
    assert_eq!(
        read(&install.bin_dir.join(".kit-installed-tag")),
        "v0.3.0\n"
    );
}

#[test]
fn pinned_downgrade_requires_allow_flag() {
    let archive = tgz_with(&[(&format!("kit-0.2.0-{TEST_TARGET}/kit"), b"x".as_slice())]);
    let origin = origin_with_release("v0.2.0", &archive);
    let install = managed_install("v0.3.0");

    let mut pinned = opts();
    pinned.version = Some("v0.2.0".to_owned());
    let (msg, _) = run_update(&pinned, &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("--allow-downgrade"), "{msg}");
}

#[test]
fn pinned_downgrade_with_allow_flag_proceeds() {
    let old_binary = script_binary("0.2.0");
    let archive = tgz_with(&[(
        &format!("kit-0.2.0-{TEST_TARGET}/kit"),
        old_binary.as_slice(),
    )]);
    let origin = origin_with_release("v0.2.0", &archive);
    let install = managed_install("v0.3.0");

    let mut pinned = opts();
    pinned.version = Some("v0.2.0".to_owned());
    pinned.allow_downgrade = true;
    let outcome = run_update(&pinned, &env_for(&origin, &install, "0.3.0")).unwrap();
    assert!(matches!(outcome, Outcome::Updated { .. }));
    assert_eq!(std::fs::read(&install.exe).unwrap(), old_binary);
    assert_eq!(
        read(&install.bin_dir.join(".kit-installed-tag")),
        "v0.2.0\n"
    );
}

#[test]
fn tampered_archive_rejected_before_swap() {
    use sha2::Digest as _;
    let new_binary = script_binary("9.9.9");
    let archive = tgz_with(&[(
        &format!("kit-9.9.9-{TEST_TARGET}/kit"),
        new_binary.as_slice(),
    )]);
    // sha256 sidecar covers DIFFERENT bytes than the served archive.
    let wrong_sha = format!(
        "{}  kit-9.9.9-{TEST_TARGET}.tar.gz\n",
        hash::to_hex_bytes(&sha2::Sha256::digest(b"not the served archive"))
    );
    let origin =
        origin_with_release_and_sha256_body("v9.9.9", &archive, Some(wrong_sha.as_bytes()));
    let install = managed_install("v0.3.0");
    let before = std::fs::read(&install.exe).unwrap();

    let (msg, _) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("sha256 mismatch"), "{msg}");
    assert_eq!(
        std::fs::read(&install.exe).unwrap(),
        before,
        "binary must be untouched"
    );
    assert_eq!(
        read(&install.bin_dir.join(".kit-installed-tag")),
        "v0.3.0\n"
    );
}

#[test]
fn unmanaged_install_refused_with_guidance() {
    let archive = tgz_with(&[(&format!("kit-9.9.9-{TEST_TARGET}/kit"), b"x".as_slice())]);
    let origin = origin_with_release("v9.9.9", &archive);
    let install = managed_install("v0.3.0");
    std::fs::remove_file(install.bin_dir.join(".kit-installed-tag")).unwrap();

    let (msg, code) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("not installer-managed"), "{msg}");
    assert_eq!(code, 69, "UNAVAILABLE");
}

#[test]
fn receipt_mismatch_refused() {
    let archive = tgz_with(&[(&format!("kit-9.9.9-{TEST_TARGET}/kit"), b"x".as_slice())]);
    let origin = origin_with_release("v9.9.9", &archive);
    let install = managed_install("v0.3.0");
    std::fs::write(install.state_dir.join("installed-tag"), "v0.1.0\n").unwrap();

    let (msg, _) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("installed-tag mismatch"), "{msg}");
}

#[test]
fn check_reports_without_touching_anything() {
    let archive = tgz_with(&[(&format!("kit-9.9.9-{TEST_TARGET}/kit"), b"x".as_slice())]);
    let origin = origin_with_release("v9.9.9", &archive);
    // --check needs no receipts at all: strip the whole install down to
    // a bare binary.
    let install = managed_install("v0.3.0");
    std::fs::remove_file(install.bin_dir.join(".kit-installed-tag")).unwrap();
    let before = std::fs::read(&install.exe).unwrap();

    let mut check = opts();
    check.check = true;
    let outcome = run_update(&check, &env_for(&origin, &install, "0.3.0")).unwrap();
    assert_eq!(
        outcome,
        Outcome::UpdateAvailable {
            current: "v0.3.0".to_owned(),
            latest: "v9.9.9".to_owned(),
        }
    );
    assert_eq!(std::fs::read(&install.exe).unwrap(), before);
}

#[test]
fn release_without_sha256_sidecar_is_refused() {
    let new_binary = script_binary("9.9.9");
    let archive = tgz_with(&[(
        &format!("kit-9.9.9-{TEST_TARGET}/kit"),
        new_binary.as_slice(),
    )]);
    let origin = origin_with_assets("v9.9.9", &archive, None, false, true);
    let install = managed_install("v0.3.0");
    let before = std::fs::read(&install.exe).unwrap();

    let (msg, _) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains(".sha256"), "{msg}");
    assert_eq!(std::fs::read(&install.exe).unwrap(), before);
}

#[test]
fn release_without_cosign_bundle_is_refused() {
    let new_binary = script_binary("9.9.9");
    let archive = tgz_with(&[(
        &format!("kit-9.9.9-{TEST_TARGET}/kit"),
        new_binary.as_slice(),
    )]);
    let origin = origin_with_assets("v9.9.9", &archive, None, true, false);
    let install = managed_install("v0.3.0");
    let before = std::fs::read(&install.exe).unwrap();

    let (msg, _) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains(".cosign.bundle"), "{msg}");
    assert_eq!(std::fs::read(&install.exe).unwrap(), before);
}

#[test]
fn rejected_signature_runs_no_downloaded_code() {
    let install = managed_install("v0.3.0");
    let marker = install.bin_dir.join("ran-downloaded-code");
    let new_binary = marker_binary("9.9.9", &marker);
    let archive = tgz_with(&[(
        &format!("kit-9.9.9-{TEST_TARGET}/kit"),
        new_binary.as_slice(),
    )]);
    let origin = origin_with_release("v9.9.9", &archive);
    let before = std::fs::read(&install.exe).unwrap();

    let mut env = env_for(&origin, &install, "0.3.0");
    env.cosign = install.cosign_bad.clone();
    let (msg, code) = run_update(&opts(), &env).unwrap_err();
    assert!(msg.contains("cosign verification failed"), "{msg}");
    assert_eq!(code, 65, "DATAERR");
    assert!(!marker.exists(), "downloaded code ran before verification");
    assert_eq!(std::fs::read(&install.exe).unwrap(), before);
    assert_eq!(
        read(&install.bin_dir.join(".kit-installed-tag")),
        "v0.3.0\n"
    );
}

#[test]
fn missing_cosign_program_is_refused() {
    let archive = tgz_with(&[(&format!("kit-9.9.9-{TEST_TARGET}/kit"), b"x".as_slice())]);
    let origin = origin_with_release("v9.9.9", &archive);
    let install = managed_install("v0.3.0");

    let mut env = env_for(&origin, &install, "0.3.0");
    env.cosign = install.bin_dir.join("no-such-cosign");
    let (msg, code) = run_update(&opts(), &env).unwrap_err();
    assert!(msg.contains("cosign"), "{msg}");
    assert_eq!(code, 69, "UNAVAILABLE");
}

#[test]
fn cosign_gets_the_pinned_signer_identity() {
    let new_binary = script_binary("9.9.9");
    let archive = tgz_with(&[(
        &format!("kit-9.9.9-{TEST_TARGET}/kit"),
        new_binary.as_slice(),
    )]);
    let origin = origin_with_release("v9.9.9", &archive);
    let install = managed_install("v0.3.0");

    run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap();
    let args = read(&install.cosign_ok.with_file_name("cosign-ok.args"));
    assert!(args.contains("verify-blob"), "{args}");
    assert!(
        args.contains(
            "--certificate-identity\nhttps://github.com/officialunofficial/kit/.github/workflows/release.yml@refs/tags/v9.9.9\n"
        ),
        "{args}"
    );
    assert!(!args.contains("regexp"), "{args}");
    assert!(
        args.contains("https://token.actions.githubusercontent.com"),
        "{args}"
    );
}

#[test]
fn asset_url_on_another_host_is_refused() {
    let mut server = mockito::Server::new();
    let archive_name = format!("kit-9.9.9-{TEST_TARGET}.tar.gz");
    let release_json = format!(
        r#"{{"tag_name":"v9.9.9","assets":[{{"name":"{archive_name}","url":"https://evil.example/assets/archive"}}]}}"#
    );
    server
        .mock("GET", "/releases/tags/v9.9.9")
        .with_body(&release_json)
        .create();
    let origin = Origin { server };
    let install = managed_install("v0.3.0");
    let before = std::fs::read(&install.exe).unwrap();

    let mut o = opts();
    o.version = Some("v9.9.9".to_owned());
    let (msg, _) = run_update(&o, &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("host differs"), "{msg}");
    assert_eq!(std::fs::read(&install.exe).unwrap(), before);
}

#[test]
fn plain_http_api_base_is_refused() {
    let origin = origin_with_release("v9.9.9", b"unused");
    let install = managed_install("v0.3.0");
    let mut env = env_for(&origin, &install, "0.3.0");
    env.allow_loopback_http = false;

    let (msg, _) = run_update(&opts(), &env).unwrap_err();
    assert!(msg.contains("non-HTTPS"), "{msg}");
}
