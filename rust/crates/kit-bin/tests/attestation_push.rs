#![allow(clippy::unwrap_used)]
include!("../../kit-sync/tests/support/attestation_fetch.rs");
use kit_core::protocol::Transport;

#[test]
fn cli_push_opt_in_and_config_publish_on_up_to_date_branches() {
    let temp = tempfile::tempdir().unwrap();
    let bare = temp.path().join("bare");
    let tx = kit_transport_file::FileTransport::new(&bare);
    let (tip, _) = attestation_fetch::code(&tx);
    let url = format!("kit+file://{}", bare.display());
    let dir = temp.path().join("clone");
    let cfg = temp.path().join("config");
    let run = |cwd: &std::path::Path, args: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_kit"))
            .args(args)
            .current_dir(cwd)
            .env("XDG_CONFIG_HOME", &cfg)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    };
    run(temp.path(), &["clone", &url, dir.to_str().unwrap()]);
    let layout = kit_core::layout::RepoLayout::single(&dir);
    let bytes = attestation_fetch::envelope(tip);
    kit_attest::store::save(&layout, &tip, &bytes).unwrap();
    let locator = "file:///private/example/repo";
    let unsafe_envelope = attestation_fetch::git_locator_envelope(tip, "git-bridge", locator);
    let (unsafe_id, _) = kit_attest::store::save(&layout, &tip, &unsafe_envelope).unwrap();
    run(&dir, &["push"]);
    assert!(
        tx.read_ref(kit_core::refs::ATTESTMAP_REF)
            .unwrap()
            .is_none()
    );
    let out = run(&dir, &["push", "--attestations"]);
    let warnings = String::from_utf8_lossy(&out.stderr);
    assert!(warnings.contains(&format!(
        "skipped git-bridge attestation {}",
        kit_core::hash::to_hex(&unsafe_id)
    )));
    assert!(!warnings.contains(locator));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("warning: publishing attestations is permanent")
    );
    assert!(
        tx.read_ref(kit_core::refs::ATTESTMAP_REF)
            .unwrap()
            .is_some()
    );
    let out = run(&dir, &["push", "--attestations"]);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("permanent"));
    let config = layout.config_file();
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("\npush.attestations = TRUE\n");
    std::fs::write(&config, text).unwrap();
    let mut env = kit_attest::envelope::decode(&bytes).unwrap();
    env.payload = String::from_utf8(env.payload)
        .unwrap()
        .replace("example.com/test/v1", "example.com/config/v1")
        .into_bytes();
    kit_attest::store::save(&layout, &tip, env.encode().unwrap().as_bytes()).unwrap();
    let before = tx.read_ref(kit_core::refs::ATTESTMAP_REF).unwrap();
    run(&dir, &["push"]);
    assert_ne!(tx.read_ref(kit_core::refs::ATTESTMAP_REF).unwrap(), before);
}
