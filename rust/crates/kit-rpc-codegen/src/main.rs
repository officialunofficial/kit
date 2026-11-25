//! Regenerates the protocol code that `kit-rpc` checks in.
//!
//! `kit-rpc-codegen rpc` writes `generated/` from the signer, SSH, verify and
//! common schemas. `kit-rpc-codegen transport` writes `generated/transport/`
//! from the canonical transport and health schemas. Both need `protoc` 27 or
//! newer on `PATH` (or in `PROTOC`), because the schemas use protobuf edition
//! 2023. Run them through `scripts/regen-rpc-proto.sh` and
//! `scripts/regen-transport-proto.sh`.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> Result<()> {
    // `rust/crates/kit-rpc-codegen` -> `rust/crates` -> `rust` -> repo root.
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let crate_dir = repo.join("rust/crates/kit-rpc");
    match std::env::args().nth(1).as_deref() {
        Some("rpc") => rpc(&repo, &crate_dir),
        Some("transport") => transport(&repo, &crate_dir),
        _ => Err("usage: kit-rpc-codegen <rpc|transport>".into()),
    }
}

/// Removes the `.rs` files directly under `dir` and makes sure it exists.
fn clear(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "rs") {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn rpc(repo: &Path, crate_dir: &Path) -> Result<()> {
    let proto_dir = crate_dir.join("proto");
    // The shared ref types (`kit.common.v1.RefExpectation` and `RefEntry`)
    // live in the repository's canonical proto root.
    let common_dir = repo.join("proto");
    let files = [
        proto_dir.join("kit/rpc/v1/common.proto"),
        proto_dir.join("kit/rpc/v1/signer/signer.proto"),
        proto_dir.join("kit/rpc/v1/ssh/ssh.proto"),
        proto_dir.join("kit/rpc/v1/verify/verify.proto"),
        common_dir.join("kit/common/v1/refs.proto"),
    ];
    let out = crate_dir.join("generated");
    clear(&out)?;
    buffa_build::Config::new()
        .files(&files)
        .includes(&[&proto_dir, &common_dir])
        .include_file("_includes.rs")
        // `arbitrary::Arbitrary` derives, gated behind kit-rpc's opt-in
        // `arbitrary` feature, for the fuzz harness.
        .generate_arbitrary(true)
        .out_dir(&out)
        .compile()?;
    Ok(())
}

fn transport(repo: &Path, crate_dir: &Path) -> Result<()> {
    let root = repo.join("proto");
    let files = [
        root.join("kit/transport/v1/transport.proto"),
        root.join("grpc/health/v1/health.proto"),
    ];
    let out = crate_dir.join("generated/transport");
    clear(&out)?;
    connectrpc_build::Config::new()
        .files(&files)
        .includes(&[&root])
        .include_file("_connectrpc.rs")
        .out_dir(&out)
        .emit_rerun_directives(false)
        .compile()?;
    gate_bindings(&out)
}

/// Keeps one generated message tree while letting a consumer leave out the
/// Connect runtime: the service bindings compile only with kit-rpc's
/// `transport` feature.
fn gate_bindings(out: &Path) -> Result<()> {
    const GATED: [(&str, &str); 2] = [
        (
            "kit.transport.v1.mod.rs",
            "include!(\"kit.transport.v1.transport.__connect.rs\");",
        ),
        (
            "grpc.health.v1.mod.rs",
            "include!(\"grpc.health.v1.health.__connect.rs\");",
        ),
    ];
    for (module, include) in GATED {
        let path: PathBuf = out.join(module);
        let source = fs::read_to_string(&path)?;
        if !source.contains(include) {
            return Err(format!("{module} has no `{include}` to gate").into());
        }
        let gated = format!("#[cfg(feature = \"transport\")]\n{include}");
        fs::write(&path, source.replace(include, &gated))?;
    }
    Ok(())
}
