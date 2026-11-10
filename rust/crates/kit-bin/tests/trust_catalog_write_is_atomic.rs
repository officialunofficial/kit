//! `kit trust add` must replace the trust catalog whole. A write that fails
//! leaves the catalog as it was, and a catalog that is a symlink stays one.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

/// The file size limit in blocks of the shell's `ulimit -f`. It is 512 bytes
/// for 512-byte blocks and 1024 bytes for 1024-byte blocks. The catalog below
/// is larger than both.
const FILE_SIZE_LIMIT_BLOCKS: u32 = 1;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

/// Run `kit trust add <keyid> <hex> --trust-roots <catalog>` under umask 022.
/// With a limit, a write past it fails with an I/O error instead of killing
/// the process.
fn trust_add(cwd: &Path, catalog: &Path, hex: &str, limited: bool) -> Output {
    let limit = if limited {
        format!("trap '' XFSZ; ulimit -f {FILE_SIZE_LIMIT_BLOCKS}; ")
    } else {
        String::new()
    };
    Command::new("sh")
        .arg("-c")
        .arg(format!("umask 022; {limit}exec \"$0\" \"$@\""))
        .arg(kit_bin())
        .args(["trust", "add", &format!("ed25519:{hex}"), hex])
        .arg("--trust-roots")
        .arg(catalog)
        .current_dir(cwd)
        .output()
        .expect("spawn sh")
}

fn entry(byte: u8) -> String {
    let hex = format!("{byte:02x}").repeat(32);
    format!(
        "[[trust_root]]\nkeyid = \"ed25519:{hex}\"\nkind = \"ed25519\"\npubkey_hex = \"{hex}\"\n\n"
    )
}

#[test]
fn a_failed_write_leaves_the_catalog_unchanged() {
    let td = tempfile::tempdir().unwrap();
    let catalog = td.path().join("trust-roots.toml");
    let before: String = (1..=10).map(entry).collect();
    fs::write(&catalog, &before).unwrap();

    let out = trust_add(td.path(), &catalog, &"ff".repeat(32), true);

    assert!(!out.status.success(), "the write should fail: {out:?}");
    assert_eq!(fs::read_to_string(&catalog).unwrap(), before);
    let names: Vec<_> = fs::read_dir(td.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["trust-roots.toml"], "temporary file left");
}

#[test]
fn a_symlinked_catalog_stays_a_symlink() {
    let td = tempfile::tempdir().unwrap();
    let real_dir = td.path().join("real");
    fs::create_dir(&real_dir).unwrap();
    let real = real_dir.join("trust-roots.toml");
    fs::write(&real, entry(1)).unwrap();
    let link = td.path().join("trust-roots.toml");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let hex = "ff".repeat(32);
    let out = trust_add(td.path(), &link, &hex, false);

    assert!(out.status.success(), "trust add failed: {out:?}");
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&link).unwrap(), real);
    let text = fs::read_to_string(&real).unwrap();
    assert!(text.contains(&format!("ed25519:{hex}")), "catalog: {text}");
    assert!(text.contains(&entry(1)), "catalog: {text}");
}

#[test]
fn a_dangling_symlinked_catalog_is_created_and_stays_a_symlink() {
    let td = tempfile::tempdir().unwrap();
    let real_dir = td.path().join("real");
    fs::create_dir(&real_dir).unwrap();
    let link = td.path().join("trust-roots.toml");
    std::os::unix::fs::symlink("real/catalog.toml", &link).unwrap();

    let hex = "ff".repeat(32);
    let out = trust_add(td.path(), &link, &hex, false);

    assert!(out.status.success(), "trust add failed: {out:?}");
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_link(&link).unwrap(),
        Path::new("real/catalog.toml")
    );
    let text = fs::read_to_string(real_dir.join("catalog.toml")).unwrap();
    assert!(text.contains(&format!("ed25519:{hex}")), "catalog: {text}");
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_catalog_keeps_its_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let td = tempfile::tempdir().unwrap();
    let catalog = td.path().join("trust-roots.toml");
    fs::write(&catalog, entry(1)).unwrap();
    // Not the 0644 that umask 022 gives a new file, so only a copy of the
    // old mode can produce it.
    fs::set_permissions(&catalog, fs::Permissions::from_mode(0o640)).unwrap();

    let out = trust_add(td.path(), &catalog, &"ff".repeat(32), false);

    assert!(out.status.success(), "trust add failed: {out:?}");
    assert_eq!(mode(&catalog), 0o640);
}

#[test]
fn a_read_only_catalog_is_refused_and_left_unchanged() {
    use std::os::unix::fs::PermissionsExt as _;

    let td = tempfile::tempdir().unwrap();
    let catalog = td.path().join("trust-roots.toml");
    let before = entry(1);
    fs::write(&catalog, &before).unwrap();
    fs::set_permissions(&catalog, fs::Permissions::from_mode(0o444)).unwrap();

    let out = trust_add(td.path(), &catalog, &"ff".repeat(32), false);

    assert!(
        !out.status.success(),
        "the write should be refused: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ermission denied"), "stderr: {stderr}");
    assert_eq!(fs::read_to_string(&catalog).unwrap(), before);
    assert_eq!(mode(&catalog), 0o444);
    let names: Vec<_> = fs::read_dir(td.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["trust-roots.toml"], "temporary file left");
}

#[test]
fn a_new_catalog_gets_the_mode_of_any_new_file() {
    let td = tempfile::tempdir().unwrap();
    let catalog = td.path().join("trust-roots.toml");

    let out = trust_add(td.path(), &catalog, &"ff".repeat(32), false);

    assert!(out.status.success(), "trust add failed: {out:?}");
    assert_eq!(mode(&catalog), 0o644);
}
