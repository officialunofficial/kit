#![allow(clippy::unwrap_used)]
include!("../../kit-sync/tests/support/attestation_fetch.rs");

#[test]
fn cli_config_opt_out_and_explicit_refetch_control_envelope_writes() {
    let temp = tempfile::tempdir().unwrap();
    let bare = temp.path().join("bare");
    let tx = kit_transport_file::FileTransport::new(&bare);
    let (tip, _) = attestation_fetch::code(&tx);
    let env = attestation_fetch::envelope(tip);
    attestation_fetch::append(&tx, &kit_attest::pack::build(&[&env], 4096).unwrap());
    let config_root = temp.path().join("config");
    std::fs::create_dir_all(config_root.join("kit")).unwrap();
    let run = |cwd: &std::path::Path, args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_kit"))
            .args(args)
            .current_dir(cwd)
            .env("XDG_CONFIG_HOME", &config_root)
            .output()
            .unwrap()
    };
    let url = format!("kit+file://{}", bare.display());
    let cloned = temp.path().join("cloned");
    let out = run(
        temp.path(),
        &["clone", "--no-attestations", &url, cloned.to_str().unwrap()],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let layout = kit_core::layout::RepoLayout::single(&cloned);
    let id = kit_core::hash::hash(&env);
    let path = kit_attest::store::envelope_path(&layout, &tip, &id);
    assert!(!path.exists());
    std::fs::write(
        config_root.join("kit/config"),
        "fetch.attestations = false\n",
    )
    .unwrap();
    let out = run(&cloned, &["fetch"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!path.exists());
    let out = run(&cloned, &["fetch", "--refetch-attestations"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&path).unwrap(), env);
    assert!(kit_sync::attestation_records::fetched_path(&layout, &id).exists());
    assert!(
        !run(
            &cloned,
            &["pull", "--no-attestations", "--refetch-attestations"]
        )
        .status
        .success()
    );
}

#[test]
fn libkit_options_offer_an_explicit_attestation_off_switch() {
    use kit_core::{
        protocol::Transport,
        refs::{ATTESTMAP_REF, RefWriteCondition},
    };
    let temp = tempfile::tempdir().unwrap();
    let tx = kit_transport_memory::MemoryTransport::new();
    attestation_fetch::code(&tx);
    tx.update_ref(ATTESTMAP_REF, RefWriteCondition::Any, &[7; 32])
        .unwrap();
    let descriptor = kit_sync::CloneRemote {
        name: "origin".into(),
        url: "kit+memory://test".into(),
        kind: "memory".into(),
    };
    kit_sync::init_clone_dir(temp.path(), &descriptor).unwrap();
    let source = kit_sync::TransportSource::new(&tx);
    let mut options = kit_sync::SyncOptions::default();
    options.attestations = false;
    let report = libkit::transfer::fetch_with_options(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert!(report.attestation_warnings.is_empty());
    options.attestations = true;
    let report = libkit::transfer::fetch_with_options(
        temp.path(),
        &source,
        "origin",
        &options,
        &kit_sync::NoopObserver,
    )
    .unwrap();
    assert_eq!(report.attestation_warnings.len(), 1);
}
