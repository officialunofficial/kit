// Guard against introducing calls to the YubiKey PIV RSA private-key
// decrypt path. This path has exposed private-key timing information in
// vulnerable RSA releases. The guard also applies if a YubiKey dependency
// is introduced again.

use std::fs;
use std::path::{Path, PathBuf};

/// Tokens that indicate a call into the vulnerable RSA decrypt path.
/// Keep this list narrow so the test does not false-positive on
/// strings that legitimately appear in comments or doc.
const FORBIDDEN_TOKENS: &[&str] = &["yubikey::piv::decrypt_data", "piv::decrypt_data"];

/// Walk `dir` recursively and collect every `.rs` file path. We bail
/// on `target/` so a cargo build with debug artifacts doesn't slow
/// the test or trip on generated code.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if path.is_dir() {
            // Skip build artifacts and vendored dependencies; we only
            // want first-party kit source.
            if file_name == "target" || file_name == ".git" || file_name == "node_modules" {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            // Skip this very test file — it has to mention the
            // forbidden tokens to assert against them.
            if file_name == "no_rsa_decrypt.rs" {
                continue;
            }
            out.push(path);
        }
    }
}

#[test]
fn workspace_does_not_call_yubikey_rsa_decrypt() {
    // CARGO_MANIFEST_DIR points at the kit-keystore crate; walk up
    // two levels to land on `rust/crates`, then one more to land on
    // `rust/`. We scan the whole `rust/` tree so any new crate that
    // grows a `yubikey::piv::decrypt_data` reference is caught.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rust_root = crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("CARGO_MANIFEST_DIR has at least two ancestors")
        .to_path_buf();

    let mut rs_files = Vec::new();
    collect_rs_files(&rust_root, &mut rs_files);
    assert!(
        !rs_files.is_empty(),
        "expected to scan some .rs files under {}",
        rust_root.display()
    );

    let mut offenders: Vec<(PathBuf, &'static str)> = Vec::new();
    for path in &rs_files {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        for token in FORBIDDEN_TOKENS {
            if contents.contains(token) {
                offenders.push((path.clone(), token));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "Workspace references the YubiKey RSA decrypt path. Offenders: {offenders:?}"
    );
}
