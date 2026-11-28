//! `kit clone` and `kit fetch` from a `kit closure export` directory:
//! an offline bundle carried on removable media.
//!
//! The export is a `kit+closure://` remote with one branch, read through
//! the same fetch that every transport uses, so the packs, the closure and
//! the signatures are checked as a network fetch checks them.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use proptest::prelude::*;

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

/// Run kit in `cwd` with a private user config under `home`.
fn kit(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(kit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", home.join("xdg"))
        .env("HOME", home)
        .env_remove("KIT_DIR")
        .output()
        .expect("spawn kit")
}

fn ok(home: &Path, cwd: &Path, args: &[&str]) -> String {
    let out = kit(home, cwd, args);
    assert!(
        out.status.success(),
        "kit {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn read_ref(repo: &Path, name: &str) -> Option<String> {
    fs::read_to_string(repo.join(".kit").join(name))
        .ok()
        .map(|s| s.trim().to_owned())
}

fn closure_url(dir: &Path) -> String {
    format!("kit+closure://{}", dir.display())
}

/// A signed repository with `commits` commits on `main`, the content of
/// commit `i` given by `files[i]`. Returns the tip of each commit.
fn repo_with(home: &Path, dir: &Path, files: &[Vec<(String, Vec<u8>)>]) -> Vec<String> {
    fs::create_dir_all(dir).unwrap();
    ok(home, dir, &["init"]);
    ok(home, dir, &["keygen"]);
    let mut tips = Vec::new();
    for (i, commit) in files.iter().enumerate() {
        for (name, body) in commit {
            fs::write(dir.join(name), body).unwrap();
            ok(home, dir, &["add", name]);
        }
        ok(
            home,
            dir,
            &["commit", "--allow-empty", "-m", &format!("c{i}")],
        );
        tips.push(read_ref(dir, "refs/heads/main").unwrap());
    }
    tips
}

fn three_commits(home: &Path, dir: &Path) -> Vec<String> {
    repo_with(
        home,
        dir,
        &[
            vec![("a.txt".into(), b"one\n".to_vec())],
            vec![("b.txt".into(), b"two\n".to_vec())],
            vec![("a.txt".into(), b"one\nthree\n".to_vec())],
        ],
    )
}

/// Export `rev` of `repo` into `out` with the extra flags.
fn export(home: &Path, repo: &Path, rev: &str, out: &Path, extra: &[&str]) {
    let out_s = out.to_str().unwrap();
    let mut args = vec!["closure", "export", rev, "-o", out_s];
    args.extend_from_slice(extra);
    ok(home, repo, &args);
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

fn pack_files(dir: &Path) -> Vec<PathBuf> {
    let mut packs: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "pack"))
        .collect();
    packs.sort();
    packs
}

/// A fresh repository with the export added as remote `usb`.
fn receiver(home: &Path, dir: &Path, export: &Path) {
    fs::create_dir_all(dir).unwrap();
    ok(home, dir, &["init"]);
    ok(home, dir, &["remote", "add", "usb", &closure_url(export)]);
}

/// The number of objects the history of `rev` holds in `repo`, checked.
fn history_objects(home: &Path, repo: &Path, rev: &str) -> u64 {
    let out = ok(
        home,
        repo,
        &["closure", "verify", rev, "--history", "--format=json"],
    );
    let json: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(json["complete"], true, "{out}");
    json["verified"].as_u64().unwrap()
}

#[test]
fn a_copied_export_clones_and_verifies() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    let tips = three_commits(home.path(), &src);
    let exported = td.path().join("x.closure");
    export(
        home.path(),
        &src,
        "main",
        &exported,
        &["--history", "--branch", "main"],
    );
    // Carry it somewhere else, as a copy to removable media would.
    let usb = td.path().join("usb").join("x.closure");
    copy_dir(&exported, &usb);
    fs::remove_dir_all(&exported).unwrap();

    let dest = td.path().join("dest");
    ok(
        home.path(),
        td.path(),
        &["clone", &closure_url(&usb), dest.to_str().unwrap()],
    );
    assert_eq!(read_ref(&dest, "refs/heads/main").unwrap(), tips[2]);
    assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"one\nthree\n");
    assert_eq!(fs::read(dest.join("b.txt")).unwrap(), b"two\n");
    ok(home.path(), &dest, &["verify", "main"]);
    assert_eq!(
        history_objects(home.path(), &dest, "main"),
        history_objects(home.path(), &src, "main")
    );
}

#[test]
fn clone_takes_a_plain_path_to_the_manifest() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    let tips = three_commits(home.path(), &src);
    let exported = td.path().join("x.closure");
    export(
        home.path(),
        &src,
        "main",
        &exported,
        &["--history", "--branch", "main"],
    );
    let manifest = exported.join("MANIFEST.mkcl");
    let dest = td.path().join("dest");
    ok(
        home.path(),
        td.path(),
        &["clone", manifest.to_str().unwrap(), dest.to_str().unwrap()],
    );
    assert_eq!(read_ref(&dest, "refs/heads/main").unwrap(), tips[2]);
    // The remote is saved as the URL of the export's directory.
    let config = fs::read_to_string(dest.join(".kit").join("config")).unwrap();
    assert!(
        config.contains(&closure_url(&exported)),
        "config does not name the export: {config}"
    );
}

#[test]
fn fetch_publishes_the_recorded_branch_as_a_tracking_ref() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    let tips = three_commits(home.path(), &src);
    let exported = td.path().join("x.closure");
    export(
        home.path(),
        &src,
        "main",
        &exported,
        &["--history", "--branch", "trunk"],
    );
    let dest = td.path().join("dest");
    receiver(home.path(), &dest, &exported);
    ok(home.path(), &dest, &["fetch", "usb"]);
    assert_eq!(read_ref(&dest, "refs/remotes/usb/trunk").unwrap(), tips[2]);
    ok(home.path(), &dest, &["verify", "refs/remotes/usb/trunk"]);
}

#[test]
fn fetch_from_a_path_without_a_remote_uses_the_name_closure() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    let tips = three_commits(home.path(), &src);
    let exported = td.path().join("x.closure");
    export(
        home.path(),
        &src,
        "main",
        &exported,
        &["--history", "--branch", "main"],
    );
    let dest = td.path().join("dest");
    fs::create_dir_all(&dest).unwrap();
    ok(home.path(), &dest, &["init"]);
    let manifest = exported.join("MANIFEST.mkcl");
    ok(home.path(), &dest, &["fetch", manifest.to_str().unwrap()]);
    assert_eq!(
        read_ref(&dest, "refs/remotes/closure/main").unwrap(),
        tips[2]
    );

    // The URL form works the same way.
    let other = td.path().join("other");
    fs::create_dir_all(&other).unwrap();
    ok(home.path(), &other, &["init"]);
    ok(home.path(), &other, &["fetch", &closure_url(&exported)]);
    assert_eq!(
        read_ref(&other, "refs/remotes/closure/main").unwrap(),
        tips[2]
    );
}

#[test]
fn a_tampered_pack_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    three_commits(home.path(), &src);
    let exported = td.path().join("x.closure");
    export(
        home.path(),
        &src,
        "main",
        &exported,
        &["--history", "--branch", "main"],
    );
    let pack = &pack_files(&exported)[0];
    let mut bytes = fs::read(pack).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    fs::write(pack, bytes).unwrap();

    let dest = td.path().join("dest");
    receiver(home.path(), &dest, &exported);
    let out = kit(home.path(), &dest, &["fetch", "usb"]);
    assert!(!out.status.success(), "a tampered pack fetched: {out:?}");
    assert_eq!(read_ref(&dest, "refs/remotes/usb/main"), None);

    let clone_dest = td.path().join("clone");
    let out = kit(
        home.path(),
        td.path(),
        &[
            "clone",
            &closure_url(&exported),
            clone_dest.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success(), "a tampered pack cloned: {out:?}");
    assert_eq!(read_ref(&clone_dest, "refs/heads/main"), None);
}

#[test]
fn a_manifest_with_a_damaged_byte_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    three_commits(home.path(), &src);
    let exported = td.path().join("x.closure");
    export(
        home.path(),
        &src,
        "main",
        &exported,
        &["--history", "--branch", "main"],
    );
    let manifest = exported.join("MANIFEST.mkcl");
    let mut bytes = fs::read(&manifest).unwrap();
    // A byte of the branch name: the name stays valid, the checksum does not.
    let at = bytes.windows(4).position(|w| w == b"main").unwrap();
    bytes[at] = b'n';
    fs::write(&manifest, bytes).unwrap();
    let dest = td.path().join("dest");
    receiver(home.path(), &dest, &exported);
    let out = kit(home.path(), &dest, &["fetch", "usb"]);
    assert!(!out.status.success(), "a damaged manifest fetched: {out:?}");
    assert!(fs::read_dir(dest.join(".kit/refs/remotes")).map_or(true, |mut d| d.next().is_none()));
}

#[test]
fn an_incremental_export_fetches_into_a_repo_that_holds_the_tag() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    let tips = three_commits(home.path(), &src);
    ok(home.path(), &src, &["tag", "v1", &tips[0]]);

    // The receiver already holds v1, from a full export of it.
    let base = td.path().join("base.closure");
    export(
        home.path(),
        &src,
        "v1",
        &base,
        &["--history", "--branch", "main"],
    );
    let dest = td.path().join("dest");
    ok(
        home.path(),
        td.path(),
        &["clone", &closure_url(&base), dest.to_str().unwrap()],
    );
    assert_eq!(read_ref(&dest, "refs/heads/main").unwrap(), tips[0]);

    // The history since v1 only.
    let inc = td.path().join("inc.closure");
    export(
        home.path(),
        &src,
        "main",
        &inc,
        &["--history", "--branch", "main", "--since", "v1"],
    );
    let full = td.path().join("full.closure");
    export(home.path(), &src, "main", &full, &["--history"]);
    let size = |dir: &Path| -> u64 {
        pack_files(dir)
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .sum()
    };
    assert!(
        size(&inc) < size(&full),
        "the incremental export is not smaller"
    );

    ok(
        home.path(),
        &dest,
        &["remote", "add", "usb", &closure_url(&inc)],
    );
    ok(home.path(), &dest, &["fetch", "usb"]);
    assert_eq!(read_ref(&dest, "refs/remotes/usb/main").unwrap(), tips[2]);
    ok(home.path(), &dest, &["verify", "refs/remotes/usb/main"]);

    // A repository without v1 cannot take it, and publishes nothing.
    let empty = td.path().join("empty");
    receiver(home.path(), &empty, &inc);
    let out = kit(home.path(), &empty, &["fetch", "usb"]);
    assert!(!out.status.success(), "fetched without its base: {out:?}");
    assert_eq!(read_ref(&empty, "refs/remotes/usb/main"), None);
}

#[test]
fn closure_verify_completes_an_incremental_export_from_the_local_store() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    let tips = three_commits(home.path(), &src);
    let inc = td.path().join("inc.closure");
    export(
        home.path(),
        &src,
        "main",
        &inc,
        &["--history", "--since", &tips[0]],
    );
    let inc_s = inc.to_str().unwrap();
    // In the source repository, which holds the base, it is complete.
    ok(
        home.path(),
        &src,
        &["closure", "verify", &tips[2], "--from", inc_s],
    );
    // Outside a repository the objects of the base are missing.
    let out = kit(
        home.path(),
        td.path(),
        &["closure", "verify", &tips[2], "--from", inc_s],
    );
    assert_eq!(out.status.code(), Some(65), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("missing"));
}

#[test]
fn an_export_without_a_branch_is_refused_by_fetch() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    three_commits(home.path(), &src);
    let exported = td.path().join("x.closure");
    export(home.path(), &src, "main", &exported, &["--history"]);
    let dest = td.path().join("dest");
    receiver(home.path(), &dest, &exported);
    let out = kit(home.path(), &dest, &["fetch", "usb"]);
    assert_eq!(out.status.code(), Some(65), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--branch"),
        "{out:?}"
    );
}

#[test]
fn an_export_without_new_flags_keeps_manifest_version_1() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    three_commits(home.path(), &src);
    let plain = td.path().join("plain.closure");
    export(home.path(), &src, "main", &plain, &["--history"]);
    let bytes = fs::read(plain.join("MANIFEST.mkcl")).unwrap();
    assert_eq!(&bytes[..5], b"KCLM\x01");
    let branched = td.path().join("branched.closure");
    export(
        home.path(),
        &src,
        "main",
        &branched,
        &["--history", "--branch", "main"],
    );
    let bytes = fs::read(branched.join("MANIFEST.mkcl")).unwrap();
    assert_eq!(&bytes[..5], b"KCLM\x02");
}

#[test]
fn export_flag_errors() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    let tips = three_commits(home.path(), &src);
    let out_dir = td.path().join("o");
    let o = out_dir.to_str().unwrap();
    let code = |args: &[&str]| kit(home.path(), &src, args).status.code();
    // --since needs history.
    assert_eq!(
        code(&["closure", "export", "main", "-o", o, "--since", &tips[0]]),
        Some(64)
    );
    // A branch name must be a valid ref name.
    assert_eq!(
        code(&[
            "closure",
            "export",
            "main",
            "-o",
            o,
            "--history",
            "--branch",
            "a b"
        ]),
        Some(64)
    );
    // An annotated tag root cannot carry a branch.
    ok(home.path(), &src, &["tag", "-a", "v1", "-m", "v1"]);
    assert_eq!(
        code(&[
            "closure",
            "export",
            "v1",
            "-o",
            o,
            "--history",
            "--branch",
            "main"
        ]),
        Some(65)
    );
}

#[test]
fn a_push_to_an_export_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    three_commits(home.path(), &src);
    let exported = td.path().join("x.closure");
    export(
        home.path(),
        &src,
        "main",
        &exported,
        &["--history", "--branch", "main"],
    );
    let before: Vec<_> = pack_files(&exported);
    ok(
        home.path(),
        &src,
        &["remote", "add", "usb", &closure_url(&exported)],
    );
    fs::write(src.join("c.txt"), b"new\n").unwrap();
    ok(home.path(), &src, &["add", "c.txt"]);
    ok(home.path(), &src, &["commit", "-m", "c3"]);
    let out = kit(home.path(), &src, &["push", "usb", "main"]);
    assert!(
        !out.status.success(),
        "a push to an export succeeded: {out:?}"
    );
    assert_eq!(pack_files(&exported), before);
}

/// Invariant: fetching the same export twice changes nothing the second
/// time.
#[test]
fn fetching_an_export_twice_changes_nothing() {
    let home = tempfile::tempdir().unwrap();
    let td = tempfile::tempdir().unwrap();
    let src = td.path().join("src");
    three_commits(home.path(), &src);
    let exported = td.path().join("x.closure");
    export(
        home.path(),
        &src,
        "main",
        &exported,
        &["--history", "--branch", "main"],
    );
    let dest = td.path().join("dest");
    receiver(home.path(), &dest, &exported);
    ok(home.path(), &dest, &["fetch", "usb"]);
    let snapshot = |repo: &Path| {
        (
            read_ref(repo, "refs/remotes/usb/main"),
            history_objects(home.path(), repo, "refs/remotes/usb/main"),
        )
    };
    let first = snapshot(&dest);
    let out = ok(home.path(), &dest, &["fetch", "usb", "--format=json"]);
    let json: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(json["updated"], serde_json::json!([]), "{out}");
    assert_eq!(snapshot(&dest), first);
}

fn history_strategy() -> impl Strategy<Value = Vec<Vec<(String, Vec<u8>)>>> {
    let file = (
        prop::sample::select(vec!["a.txt", "b.txt", "dir/c.txt"]),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(n, b)| (n.to_owned(), b));
    prop::collection::vec(prop::collection::vec(file, 1..3), 1..4)
}

fn with_dirs(files: &[Vec<(String, Vec<u8>)>], dir: &Path) {
    for commit in files {
        for (name, _) in commit {
            if let Some(parent) = Path::new(name).parent() {
                fs::create_dir_all(dir.join(parent)).unwrap();
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 6, failure_persistence: None, ..ProptestConfig::default() })]

    /// Invariant: fetching an export of `--history <rev>` yields the same
    /// tip and objects as fetching `<rev>` from a file remote.
    #[test]
    fn an_export_fetches_what_a_file_remote_fetches(files in history_strategy()) {
        let home = tempfile::tempdir().unwrap();
        let td = tempfile::tempdir().unwrap();
        let src = td.path().join("src");
        fs::create_dir_all(&src).unwrap();
        with_dirs(&files, &src);
        let tips = repo_with(home.path(), &src, &files);
        let bare = td.path().join("bare");
        fs::create_dir_all(&bare).unwrap();
        let file_url = format!("kit+file://{}", bare.display());
        ok(home.path(), &src, &["remote", "add", "mirror", &file_url]);
        ok(home.path(), &src, &["push", "mirror", "main"]);
        let exported = td.path().join("x.closure");
        export(home.path(), &src, "main", &exported, &["--history", "--branch", "main"]);

        let by_file = td.path().join("by_file");
        fs::create_dir_all(&by_file).unwrap();
        ok(home.path(), &by_file, &["init"]);
        ok(home.path(), &by_file, &["remote", "add", "r", &file_url]);
        ok(home.path(), &by_file, &["fetch", "r", "--no-tags"]);
        let by_export = td.path().join("by_export");
        receiver(home.path(), &by_export, &exported);
        ok(home.path(), &by_export, &["fetch", "usb"]);

        let tip_file = read_ref(&by_file, "refs/remotes/r/main").unwrap();
        let tip_export = read_ref(&by_export, "refs/remotes/usb/main").unwrap();
        prop_assert_eq!(&tip_file, tips.last().unwrap());
        prop_assert_eq!(&tip_export, &tip_file);
        let objects = |repo: &Path, rev: &str| {
            let out = ok(home.path(), repo, &[
                "closure", "verify", rev, "--history", "--show-unreferenced", "--format=json",
            ]);
            let json: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
            (json["verified"].clone(), json["unreferenced"].clone())
        };
        prop_assert_eq!(
            objects(&by_export, "refs/remotes/usb/main"),
            objects(&by_file, "refs/remotes/r/main")
        );
    }

    /// Invariant: any flipped byte in a pack or the manifest makes the
    /// fetch fail with nothing published.
    #[test]
    fn a_flipped_byte_fails_the_fetch_closed(file_pick in any::<prop::sample::Index>(), at in any::<prop::sample::Index>(), bit in 0u8..8) {
        let home = tempfile::tempdir().unwrap();
        let td = tempfile::tempdir().unwrap();
        let src = td.path().join("src");
        three_commits(home.path(), &src);
        let exported = td.path().join("x.closure");
        export(home.path(), &src, "main", &exported, &["--history", "--branch", "main"]);
        let mut files = pack_files(&exported);
        files.push(exported.join("MANIFEST.mkcl"));
        let target = file_pick.get(&files);
        let mut bytes = fs::read(target).unwrap();
        let i = at.index(bytes.len());
        bytes[i] ^= 1 << bit;
        fs::write(target, bytes).unwrap();

        let dest = td.path().join("dest");
        receiver(home.path(), &dest, &exported);
        let out = kit(home.path(), &dest, &["fetch", "usb"]);
        prop_assert!(!out.status.success(), "flipped byte {} of {} fetched", i, target.display());
        prop_assert_eq!(read_ref(&dest, "refs/remotes/usb/main"), None);
    }
}
