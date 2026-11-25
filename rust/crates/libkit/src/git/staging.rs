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
    "remote.origin.url",
];

/// Files in the mirror directory that make git read configuration from
/// somewhere else.
const REDIRECTING_FILES: &[&str] = &["commondir", "config.worktree", "gitdir"];

/// Check the mirror at `staging` and return the url it fetches from.
///
/// # Errors
/// [`Class::Config`] when the mirror is a link, has a file that redirects
/// git's configuration, or has a configuration key that kit does not write.
/// [`Class::Unavailable`] when `git` cannot read the configuration.
pub(crate) fn check_mirror(staging: &Path) -> Result<Option<String>, Error> {
    let refuse = |why: String| {
        plain(
            Class::Config,
            format!(
                "refusing the staging mirror {}: {why}. Delete the mirror and run the command \
                 again to rebuild it",
                staging.display()
            ),
        )
    };
    let meta = std::fs::symlink_metadata(staging).map_err(|e| refuse(e.to_string()))?;
    if !meta.is_dir() {
        return Err(refuse("it is not a plain directory".to_owned()));
    }
    for name in REDIRECTING_FILES {
        if std::fs::symlink_metadata(staging.join(name)).is_ok() {
            return Err(refuse(format!("it has a `{name}` file")));
        }
    }
    let config = staging.join("config");
    let meta = std::fs::symlink_metadata(&config).map_err(|e| refuse(e.to_string()))?;
    if !meta.is_file() {
        return Err(refuse("its config is not a plain file".to_owned()));
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
        return Err(refuse(format!(
            "git cannot read its config: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let mut origin = None;
    for entry in String::from_utf8_lossy(&out.stdout).split('\0') {
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('\n').unwrap_or((entry, ""));
        if !MIRROR_KEYS.contains(&key) {
            return Err(refuse(format!("its config sets `{key}`")));
        }
        if key == "remote.origin.url" {
            origin = Some(value.trim().to_owned());
        }
    }
    Ok(origin)
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
            ("extensions.refstorage", "reftable"),
        ] {
            git(&m, &["config", key, value]);
        }
        assert!(check_mirror(&m).unwrap().is_some());
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
        assert!(refusal(&m).contains("not a plain file"));
    }
}
