//! The worktree path helpers that a removal or a write calls before it
//! touches a repo-relative path.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::fs;

use kit_core::worktree::{path_for_write, path_under_real_dirs};

/// The Kelvin sign spelling of `.kit`: the same entry as `.kit` on a
/// filesystem that folds Unicode (APFS), another name elsewhere.
const KELVIN_KIT: &str = ".\u{212A}it";

#[test]
fn a_path_in_real_directories_is_returned() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    fs::create_dir_all(r.join("a/b")).unwrap();
    assert_eq!(
        path_under_real_dirs(r, "a/b/f").unwrap(),
        Some(r.join("a/b/f"))
    );
    assert_eq!(path_under_real_dirs(r, "f").unwrap(), Some(r.join("f")));
    assert_eq!(path_for_write(r, "a/b/f").unwrap(), Some(r.join("a/b/f")));
}

#[test]
fn a_missing_ancestor_is_no_removal_but_a_write_may_create_it() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    assert_eq!(path_under_real_dirs(r, "n/m/f").unwrap(), None);
    assert_eq!(path_for_write(r, "n/m/f").unwrap(), Some(r.join("n/m/f")));
}

#[test]
fn a_file_ancestor_is_refused_for_both() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    fs::write(r.join("f"), b"f").unwrap();
    assert_eq!(path_under_real_dirs(r, "f/x").unwrap(), None);
    assert_eq!(path_for_write(r, "f/x").unwrap(), None);
}

#[cfg(unix)]
#[test]
fn a_symlinked_ancestor_is_refused_for_both() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    fs::create_dir(r.join("sub")).unwrap();
    std::os::unix::fs::symlink("sub", r.join("d")).unwrap();
    assert_eq!(path_under_real_dirs(r, "d/x").unwrap(), None);
    assert_eq!(path_for_write(r, "d/x").unwrap(), None);
    // The link itself is a path that a removal may name.
    assert_eq!(path_under_real_dirs(r, "d").unwrap(), Some(r.join("d")));
}

/// The alias is the same filesystem entry as `.kit`. A hard link makes one
/// on every Unix filesystem, so this runs where the Kelvin spelling does
/// not fold.
#[cfg(unix)]
#[test]
fn a_component_that_is_the_same_entry_as_dot_kit_is_refused() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    fs::write(r.join(".kit"), b"kitdir: elsewhere\n").unwrap();
    fs::hard_link(r.join(".kit"), r.join("caf\u{e9}")).unwrap();
    assert_eq!(path_under_real_dirs(r, "caf\u{e9}").unwrap(), None);
    assert_eq!(path_for_write(r, "caf\u{e9}").unwrap(), None);
    // An unrelated non-ASCII name stays fine.
    assert_eq!(
        path_under_real_dirs(r, "na\u{ef}ve").unwrap(),
        Some(r.join("na\u{ef}ve"))
    );
}

#[test]
fn the_kelvin_spelling_of_dot_kit_is_refused_where_it_folds() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    fs::create_dir_all(r.join(".kit")).unwrap();
    fs::create_dir_all(r.join("n/.kit")).unwrap();
    let folds = r.join(KELVIN_KIT).exists();
    for rel in [format!("{KELVIN_KIT}/HEAD"), format!("n/{KELVIN_KIT}/HEAD")] {
        let allowed = path_under_real_dirs(r, &rel).unwrap();
        let writable = path_for_write(r, &rel).unwrap();
        if folds {
            assert_eq!((allowed, writable), (None, None), "{rel}");
        }
    }
}

/// An error other than a missing ancestor is an error, not a missing path:
/// the caller must not take it for a path that a write may create.
#[test]
fn an_ancestor_that_cannot_be_examined_is_an_error() {
    let td = tempfile::tempdir().unwrap();
    let long = "x".repeat(300);
    let rel = format!("{long}/f");
    assert!(path_under_real_dirs(td.path(), &rel).is_err());
    assert!(path_for_write(td.path(), &rel).is_err());
}

/// A non-ASCII name is no alias of `.kit` when no `.kit` sits beside it,
/// whether the name exists or not.
#[test]
fn a_non_ascii_name_is_fine_without_a_dot_kit_beside_it() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    assert_eq!(
        path_under_real_dirs(r, "caf\u{e9}").unwrap(),
        Some(r.join("caf\u{e9}"))
    );
    fs::write(r.join("caf\u{e9}"), b"x").unwrap();
    assert_eq!(
        path_under_real_dirs(r, "caf\u{e9}").unwrap(),
        Some(r.join("caf\u{e9}"))
    );
    assert_eq!(
        path_for_write(r, "caf\u{e9}/f").unwrap(),
        None,
        "a file is no directory to write below"
    );
}

/// A non-ASCII name that is another entry than the `.kit` beside it is fine.
#[test]
fn a_non_ascii_name_beside_a_dot_kit_is_fine() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    fs::create_dir(r.join(".kit")).unwrap();
    fs::create_dir(r.join("caf\u{e9}")).unwrap();
    assert_eq!(
        path_under_real_dirs(r, "caf\u{e9}/f").unwrap(),
        Some(r.join("caf\u{e9}/f"))
    );
    assert_eq!(
        path_for_write(r, "caf\u{e9}/f").unwrap(),
        Some(r.join("caf\u{e9}/f"))
    );
}

/// The Kelvin spelling of `.kit` is refused at any depth, whether or not a
/// `.kit` or the parent directory exists yet, on any filesystem.
#[test]
fn the_kelvin_spelling_is_refused_below_a_missing_directory() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    for rel in [
        ".\u{212A}it/config",
        "n/.\u{212A}it/config",
        "n/m/.\u{212A}it",
    ] {
        assert_eq!(path_for_write(r, rel).unwrap(), None, "{rel}");
        assert_eq!(path_under_real_dirs(r, rel).unwrap(), None, "{rel}");
    }
    fs::create_dir(r.join("n")).unwrap();
    assert_eq!(path_for_write(r, "n/.\u{212A}it/config").unwrap(), None);
}

/// A path that is empty, absolute or has a `.` or `..` part names nothing
/// under the root and is refused.
#[test]
fn a_path_that_leaves_the_root_is_refused() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    fs::create_dir(r.join("d")).unwrap();
    for rel in ["", "/etc/x", "d/../x", "./x", "d/./x", "d//x", "../x"] {
        assert_eq!(path_for_write(r, rel).unwrap(), None, "{rel:?}");
        assert_eq!(path_under_real_dirs(r, rel).unwrap(), None, "{rel:?}");
    }
}

/// A missing directory below the root still gives the path to create.
#[test]
fn a_missing_directory_gives_the_path_below_it() {
    let td = tempfile::tempdir().unwrap();
    let r = td.path();
    assert_eq!(path_for_write(r, "a/b/c").unwrap(), Some(r.join("a/b/c")));
    fs::create_dir(r.join("a")).unwrap();
    assert_eq!(path_for_write(r, "a/b/c").unwrap(), Some(r.join("a/b/c")));
}
