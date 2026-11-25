//! The staging mirror of a bridge state directory.
//!
//! `.kit/git/<name>/repo.git` is a bare git repository that kit creates with
//! `git clone --bare` or `git init --bare` and then runs `git` in. Git applies
//! the mirror's own configuration, and some keys (`core.sshCommand`,
//! `remote.origin.uploadpack`, a credential helper) name programs or rewrite
//! the url of a remote. A `commondir` file makes git read the configuration of
//! another directory.
//!
//! The mirror is kit's own state, so kit accepts only the shape that git
//! writes when kit creates it and refuses anything else before it runs `git`
//! there.

use std::path::Path;
use std::process::{Command, Stdio};

use super::{Class, Error, plain};

/// The configuration keys that `git clone --bare` and `git init --bare` write
/// on any platform and in any shared-repository or reftable setup. Section and
/// variable names are lower case, the way `git config --list` prints them. A
/// key outside this list is refused.
const MIRROR_KEYS: &[&str] = &[
    "core.repositoryformatversion",
    "core.filemode",
    "core.bare",
    "core.ignorecase",
    "core.precomposeunicode",
    "core.symlinks",
    "core.logallrefupdates",
    "core.sharedrepository",
    "receive.denynonfastforwards",
    "extensions.objectformat",
    "extensions.compatobjectformat",
    "extensions.refstorage",
    "extensions.submodulepathconfig",
    "remote.origin.url",
];

/// Files in the mirror directory that make git read configuration or objects
/// from somewhere else. Kit never creates one.
const REDIRECTING_FILES: &[&str] = &[
    "commondir",
    "config.worktree",
    "gitdir",
    "objects/info/alternates",
    "objects/info/http-alternates",
];

/// What to do about a refused mirror. A mirror that is missing is rebuilt the
/// same way.
const REBUILD: &str = "Delete the mirror and run `kit git import <url> --remote-name <name>` (or \
                       the export) again to rebuild it; a fork-mode mirror loses its export refs";

fn refuse(staging: &Path, why: impl std::fmt::Display) -> Error {
    plain(
        Class::Config,
        format!(
            "refusing the staging mirror {}: {why}. {REBUILD}",
            staging.display()
        ),
    )
}

/// Refuse a mirror location that is not a plain directory. A location that
/// does not exist is fine: the command creates it.
///
/// # Errors
/// [`Class::Config`] when `staging` is a link or a file.
pub(crate) fn check_location(staging: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(staging) {
        Ok(meta) if !meta.is_dir() => Err(refuse(staging, "it is not a plain directory")),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(refuse(staging, e)),
    }
}

/// Refuse a link or a special file anywhere in the mirror. Git follows a link
/// to a directory such as `refs` or `objects` and reads and writes the
/// repository it points at. Kit and git never make one. The files inside the
/// two-hex-digit object directories are not listed: a link there names one
/// file, and git checks the id of what it reads.
fn check_entries(staging: &Path, dir: &Path) -> Result<(), Error> {
    let entries = std::fs::read_dir(dir).map_err(|e| refuse(staging, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| refuse(staging, e))?;
        let kind = entry.file_type().map_err(|e| refuse(staging, e))?;
        let path = entry.path();
        if kind.is_dir() {
            let name = entry.file_name();
            let loose = name.len() == 2
                && name
                    .to_str()
                    .is_some_and(|n| n.bytes().all(|b| b.is_ascii_hexdigit()))
                && dir.file_name().is_some_and(|d| d == "objects");
            if !loose {
                check_entries(staging, &path)?;
            }
        } else if !kind.is_file() {
            let shown = path
                .strip_prefix(staging)
                .unwrap_or(&path)
                .display()
                .to_string();
            return Err(refuse(
                staging,
                format!("`{shown}` is a link or a special file"),
            ));
        }
    }
    Ok(())
}

/// Check the mirror at `staging` and return the url it fetches from.
///
/// # Errors
/// [`Class::NoInput`] when the mirror does not exist. [`Class::Config`] when
/// the mirror is a link, holds a link or a special file, has a file that
/// redirects git's configuration or objects, has a configuration key that kit
/// does not write, or is not the repository that git uses for that directory.
/// [`Class::Unavailable`] when `git` cannot read the configuration.
pub(crate) fn check_mirror(staging: &Path) -> Result<Option<String>, Error> {
    if !staging.exists() && std::fs::symlink_metadata(staging).is_err() {
        return Err(plain(
            Class::NoInput,
            format!(
                "the staging mirror {} is missing; run `kit git import <url> --remote-name \
                 <name>` (or the export) again to rebuild it",
                staging.display()
            ),
        ));
    }
    check_location(staging)?;
    check_entries(staging, staging)?;
    for name in REDIRECTING_FILES {
        if std::fs::symlink_metadata(staging.join(name)).is_ok() {
            return Err(refuse(staging, format!("it has a `{name}` file")));
        }
    }
    let config = staging.join("config");
    let meta = std::fs::symlink_metadata(&config).map_err(|e| refuse(staging, e))?;
    if !meta.is_file() {
        return Err(refuse(staging, "its config is not a plain file"));
    }

    // `--file` reads that one file and nothing else: no includes, and no
    // configuration of the directory that the command runs in.
    let mut command = Command::new("git");
    kit_git_bridge::gitsrc::apply_hygiene(&mut command);
    let root = if cfg!(windows) { "C:\\" } else { "/" };
    let out = command
        .current_dir(root)
        .arg("config")
        .arg("--file")
        .arg(&config)
        .args(["--no-includes", "--list", "-z"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| plain(Class::Unavailable, format!("spawn git config: {e}")))?;
    if !out.status.success() {
        return Err(refuse(
            staging,
            format!(
                "git cannot read its config: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    let mut origin = None;
    let mut seen = Vec::new();
    for entry in String::from_utf8_lossy(&out.stdout).split('\0') {
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('\n').unwrap_or((entry, ""));
        if !MIRROR_KEYS.contains(&key) {
            return Err(refuse(staging, format!("its config sets `{key}`")));
        }
        // Kit's mirrors never repeat a key, and `git config --get` and
        // `git fetch` read a repeated `remote.origin.url` differently.
        if seen.contains(&key) {
            return Err(refuse(staging, format!("its config sets `{key}` twice")));
        }
        seen.push(key);
        if key == "remote.origin.url" {
            origin = Some(value.trim().to_owned());
        }
    }

    // Every later `git -C <mirror>` must use this directory as its
    // repository, and not search upward for another one: a `.git` entry in
    // any case, or a missing or invalid `HEAD`, would send it elsewhere.
    let used = kit_git_bridge::gitsrc::git_command(staging)
        .args(["rev-parse", "--absolute-git-dir"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| plain(Class::Unavailable, format!("spawn git rev-parse: {e}")))?;
    let same = reported_path(&used.stdout)
        .and_then(|p| std::fs::canonicalize(p).ok())
        .zip(std::fs::canonicalize(staging).ok())
        .is_some_and(|(reported, own)| reported == own);
    if !used.status.success() || !same {
        return Err(refuse(
            staging,
            format!(
                "git does not use it as its own repository: {}",
                String::from_utf8_lossy(&used.stderr).trim()
            ),
        ));
    }
    Ok(origin)
}

/// The path that `git rev-parse` printed, without its line end.
fn reported_path(stdout: &[u8]) -> Option<std::path::PathBuf> {
    let line = stdout.strip_suffix(b"\n").unwrap_or(stdout);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(line)))
    }
    #[cfg(not(unix))]
    {
        Some(std::path::PathBuf::from(
            String::from_utf8_lossy(line).into_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
    }

    /// A mirror the way `import` makes it, from an empty local upstream.
    fn mirror(root: &Path) -> std::path::PathBuf {
        let up = root.join("up");
        std::fs::create_dir(&up).unwrap();
        git(&up, &["init", "--quiet", "--bare", "."]);
        let mirror = root.join("repo.git");
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["clone", "--bare", "--quiet"])
            .arg(&up)
            .arg("repo.git")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        mirror
    }

    fn refusal(staging: &Path) -> String {
        check_mirror(staging).unwrap_err().to_string()
    }

    #[test]
    fn a_mirror_that_git_made_passes_and_reports_its_origin() {
        let tmp = tempfile::tempdir().unwrap();
        let m = mirror(tmp.path());
        let origin = check_mirror(&m).unwrap().unwrap();
        assert!(origin.ends_with("up"), "{origin}");
    }

    #[test]
    fn the_keys_of_a_shared_or_reftable_mirror_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let m = mirror(tmp.path());
        for (key, value) in [
            ("core.sharedrepository", "group"),
            ("receive.denyNonFastForwards", "true"),
        ] {
            git(&m, &["config", key, value]);
        }
        assert!(check_mirror(&m).unwrap().is_some());

        // A reftable mirror, where this git can make one.
        let reftable = tmp.path().join("reftable.git");
        let made = Command::new("git")
            .args(["init", "--quiet", "--bare", "--ref-format=reftable"])
            .arg(&reftable)
            .output()
            .unwrap()
            .status
            .success();
        if made {
            check_mirror(&reftable).unwrap();
        }
    }

    #[test]
    fn a_key_that_starts_a_program_is_refused() {
        for extra in [
            "[remote \"origin\"]\n\tuploadpack = touch x\n",
            "[core]\n\tsshCommand = touch x\n",
            "[credential]\n\thelper = !touch x\n",
            "[protocol \"ext\"]\n\tallow = always\n",
            "[include]\n\tpath = elsewhere\n",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let m = mirror(tmp.path());
            let mut text = std::fs::read_to_string(m.join("config")).unwrap();
            text.push_str(extra);
            std::fs::write(m.join("config"), text).unwrap();
            let why = refusal(&m);
            assert!(why.contains("its config sets"), "{extra}: {why}");
        }
    }

    #[test]
    fn a_file_that_redirects_the_configuration_is_refused() {
        for name in REDIRECTING_FILES {
            let tmp = tempfile::tempdir().unwrap();
            let m = mirror(tmp.path());
            std::fs::write(m.join(name), "../elsewhere\n").unwrap();
            let why = refusal(&m);
            assert!(why.contains(name), "{name}: {why}");
        }
    }

    #[test]
    fn a_repeated_key_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let m = mirror(tmp.path());
        git(&m, &["config", "--add", "remote.origin.url", "/elsewhere"]);
        assert!(refusal(&m).contains("twice"));
    }

    #[test]
    fn an_alternates_file_is_refused() {
        for name in ["alternates", "http-alternates"] {
            let tmp = tempfile::tempdir().unwrap();
            let m = mirror(tmp.path());
            std::fs::write(m.join("objects/info").join(name), "/elsewhere\n").unwrap();
            assert!(refusal(&m).contains(name), "{name}");
        }
    }

    /// Git looks for `<dir>/.git` before it takes `<dir>` for a git
    /// directory, and for a parent when `<dir>` is not one.
    #[test]
    fn a_mirror_that_git_would_not_use_as_its_repository_is_refused() {
        // A `.git` directory and a `.git` file inside the mirror.
        let tmp = tempfile::tempdir().unwrap();
        let m = mirror(tmp.path());
        let inner = m.join(".git");
        std::fs::create_dir(&inner).unwrap();
        git(&inner, &["init", "--quiet", "--bare", "."]);
        assert!(refusal(&m).contains("its own repository"));
        std::fs::remove_dir_all(&inner).unwrap();
        std::fs::write(m.join(".git"), "gitdir: /elsewhere\n").unwrap();
        assert!(refusal(&m).contains("its own repository"));

        // A mirror without a `HEAD`, below a directory that is a repository.
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        std::fs::create_dir(&state).unwrap();
        git(&state, &["init", "--quiet", "--bare", "."]);
        let m = mirror(&state);
        std::fs::remove_file(m.join("HEAD")).unwrap();
        assert!(refusal(&m).contains("its own repository"));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_or_special_file_inside_the_mirror_is_refused() {
        for name in ["refs", "objects", "packed-refs", "logs"] {
            let tmp = tempfile::tempdir().unwrap();
            let m = mirror(tmp.path());
            let other = tmp.path().join("other");
            std::fs::create_dir(&other).unwrap();
            let target = m.join(name);
            if target.is_dir() {
                std::fs::remove_dir_all(&target).unwrap();
            } else {
                let _ = std::fs::remove_file(&target);
            }
            std::os::unix::fs::symlink(&other, &target).unwrap();
            let why = refusal(&m);
            assert!(why.contains("link or a special file"), "{name}: {why}");
        }
        // A link below a directory, and a pipe where `HEAD` goes.
        let tmp = tempfile::tempdir().unwrap();
        let m = mirror(tmp.path());
        std::os::unix::fs::symlink(tmp.path(), m.join("refs/heads/x")).unwrap();
        assert!(refusal(&m).contains("refs/heads/x"));
        std::fs::remove_file(m.join("refs/heads/x")).unwrap();
        std::fs::remove_file(m.join("HEAD")).unwrap();
        let made = Command::new("mkfifo").arg(m.join("HEAD")).status().unwrap();
        assert!(made.success());
        assert!(refusal(&m).contains("HEAD"));
    }

    #[test]
    fn a_missing_mirror_says_how_to_rebuild_it() {
        let tmp = tempfile::tempdir().unwrap();
        let why = refusal(&tmp.path().join("repo.git"));
        assert!(
            why.contains("is missing") && why.contains("kit git import"),
            "{why}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_mirror_that_is_a_link_is_refused_before_anything_is_created() {
        let tmp = tempfile::tempdir().unwrap();
        let other = tmp.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let link = tmp.path().join("repo.git");
        std::os::unix::fs::symlink(&other, &link).unwrap();
        assert!(check_location(&link).is_err());
        assert!(check_location(&tmp.path().join("absent")).is_ok());
        assert_eq!(std::fs::read_dir(&other).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_mirror_or_config_that_is_a_link_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let m = mirror(tmp.path());
        let moved = tmp.path().join("moved.git");
        std::fs::rename(&m, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &m).unwrap();
        assert!(refusal(&m).contains("not a plain directory"));

        let tmp = tempfile::tempdir().unwrap();
        let m = mirror(tmp.path());
        let real = tmp.path().join("real-config");
        std::fs::rename(m.join("config"), &real).unwrap();
        std::os::unix::fs::symlink(&real, m.join("config")).unwrap();
        assert!(refusal(&m).contains("link or a special file"));
    }
}
