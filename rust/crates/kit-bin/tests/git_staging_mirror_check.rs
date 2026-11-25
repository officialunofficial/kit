//! The staging mirror under `.kit/git/<name>/repo.git` is read by `git`, and git
//! applies the mirror's own configuration. Every command that runs `git` there
//! first checks that the mirror has the shape kit creates.
#![cfg(feature = "git-bridge")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Up Stream")
        .env("GIT_AUTHOR_EMAIL", "up@example.com")
        .env("GIT_COMMITTER_NAME", "Up Stream")
        .env("GIT_COMMITTER_EMAIL", "up@example.com")
        .output()
        .expect("spawn git");
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

struct Fixture {
    root: tempfile::TempDir,
    home: tempfile::TempDir,
}

impl Fixture {
    /// A git upstream with one commit, imported into `fork/` as `up`.
    fn imported() -> Self {
        let f = Self {
            root: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
        };
        let up = f.root.path().join("upstream");
        std::fs::create_dir(&up).unwrap();
        git(&up, &["init", "--quiet", "--initial-branch=main", "."]);
        std::fs::write(up.join("a.txt"), "hello\n").unwrap();
        git(&up, &["add", "a.txt"]);
        git(&up, &["commit", "--quiet", "-m", "first"]);
        let out = f.kit(
            f.root.path(),
            &[
                "git",
                "import",
                up.to_str().unwrap(),
                "fork",
                "--remote-name",
                "up",
            ],
        );
        assert!(out.status.success(), "{out:?}");
        // A second commit gives the next fetch something to do.
        std::fs::write(up.join("b.txt"), "world\n").unwrap();
        git(&up, &["add", "b.txt"]);
        git(&up, &["commit", "--quiet", "-m", "second"]);
        f
    }

    fn kit(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_kit"))
            .args(args)
            .current_dir(cwd)
            .env("XDG_CONFIG_HOME", self.home.path())
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_GLOBAL", self.home.path().join(".gitconfig"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::null())
            .output()
            .expect("spawn kit")
    }

    fn fork(&self) -> PathBuf {
        self.root.path().join("fork")
    }

    fn mirror(&self) -> PathBuf {
        self.fork().join(".kit/git/up/repo.git")
    }

    fn marker(&self) -> PathBuf {
        self.root.path().join("ran")
    }

    fn append_to_mirror_config(&self, text: &str) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.mirror().join("config"))
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    /// Run `kit git fetch` and require that it refuses and runs nothing.
    fn fetch_refuses(&self) {
        let out = self.kit(&self.fork(), &["git", "fetch", "--remote-name", "up"]);
        assert!(!out.status.success(), "fetch went ahead: {out:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("refusing the staging mirror"), "{err}");
        assert!(!self.marker().exists(), "a program started: {err}");
    }
}

#[test]
fn fetch_refuses_a_mirror_with_an_uploadpack_key() {
    let f = Fixture::imported();
    f.append_to_mirror_config(&format!(
        "[remote \"origin\"]\n\tuploadpack = touch {}; git-upload-pack\n",
        f.marker().display()
    ));
    f.fetch_refuses();
}

#[test]
fn fetch_refuses_a_mirror_with_an_ssh_command_key() {
    let f = Fixture::imported();
    f.append_to_mirror_config(&format!(
        "[core]\n\tsshCommand = touch {}; false\n",
        f.marker().display()
    ));
    f.fetch_refuses();
}

#[test]
fn fetch_refuses_a_mirror_with_a_commondir_file() {
    let f = Fixture::imported();
    let common = f.root.path().join("common.git");
    git(f.root.path(), &["init", "--quiet", "--bare", "common.git"]);
    let url = f.root.path().join("upstream");
    std::fs::write(
        common.join("config"),
        format!(
            "[remote \"origin\"]\n\tuploadpack = touch {}; git-upload-pack\n\turl = {}\n",
            f.marker().display(),
            url.display()
        ),
    )
    .unwrap();
    std::fs::write(
        f.mirror().join("commondir"),
        format!("{}\n", common.display()),
    )
    .unwrap();
    f.fetch_refuses();
}

#[cfg(unix)]
#[test]
fn fetch_refuses_a_mirror_that_is_a_link() {
    let f = Fixture::imported();
    let elsewhere = f.root.path().join("elsewhere.git");
    std::fs::rename(f.mirror(), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, f.mirror()).unwrap();
    f.fetch_refuses();
}

#[test]
fn verify_refuses_a_mirror_with_an_unexpected_key() {
    let f = Fixture::imported();
    f.append_to_mirror_config(&format!(
        "[core]\n\tsshCommand = touch {}; false\n",
        f.marker().display()
    ));
    let out = f.kit(&f.fork(), &["git", "verify", "--remote-name", "up"]);
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refusing the staging mirror"),
        "{out:?}"
    );
    assert!(!f.marker().exists());
}

#[test]
fn an_untouched_state_still_fetches() {
    let f = Fixture::imported();
    let out = f.kit(&f.fork(), &["git", "fetch", "--remote-name", "up"]);
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("imported")
            || String::from_utf8_lossy(&out.stderr).contains("imported"),
        "{out:?}"
    );
}

#[test]
fn export_refuses_a_mirror_with_a_url_rewrite() {
    let f = Fixture::imported();
    let mirror = f.root.path().join("mirror");
    let dest = mirror.to_str().unwrap();
    let run = || {
        f.kit(
            &f.fork(),
            &["git", "export", dest, "--remote-name", "m", "--no-attest"],
        )
    };
    let out = run();
    assert!(out.status.success(), "{out:?}");

    // A rewrite in the staging config would send the next push elsewhere.
    let other = f.root.path().join("other");
    git(f.root.path(), &["init", "--quiet", "--bare", "other"]);
    let staging = f.fork().join(".kit/git/m/repo.git");
    git(
        &staging,
        &[
            "config",
            &format!("url.{}.insteadOf", other.display()),
            dest,
        ],
    );
    let out = run();
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refusing the staging mirror"),
        "{out:?}"
    );
    assert!(!other.join("refs/heads/main").exists());
}

/// A template directory in the user's git config is not copied into a mirror
/// that kit creates, so the mirror keeps the shape the check accepts.
#[test]
fn a_template_directory_is_not_copied_into_a_new_mirror() {
    let root = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let template = root.path().join("template");
    std::fs::create_dir_all(template.join("hooks")).unwrap();
    std::fs::write(template.join("config"), "[core]\n\tsshCommand = true\n").unwrap();
    std::fs::write(template.join("hooks/pre-push"), "#!/bin/sh\n").unwrap();
    let global = home.path().join(".gitconfig");
    std::fs::write(
        &global,
        format!("[init]\n\ttemplateDir = {}\n", template.display()),
    )
    .unwrap();

    let up = root.path().join("upstream");
    std::fs::create_dir(&up).unwrap();
    git(&up, &["init", "--quiet", "--initial-branch=main", "."]);
    std::fs::write(up.join("a.txt"), "hello\n").unwrap();
    git(&up, &["add", "a.txt"]);
    git(&up, &["commit", "--quiet", "-m", "first"]);

    let fork = root.path().join("fork");
    let kit = |cwd: &Path, args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_kit"))
            .args(args)
            .current_dir(cwd)
            .env("XDG_CONFIG_HOME", home.path())
            .env("HOME", home.path())
            .env("GIT_CONFIG_GLOBAL", &global)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::null())
            .output()
            .expect("spawn kit");
        assert!(out.status.success(), "kit {args:?}: {out:?}");
    };
    let import = [
        "git",
        "import",
        up.to_str().unwrap(),
        "fork",
        "--remote-name",
        "up",
    ];
    kit(root.path(), &import);
    kit(&fork, &["git", "fetch", "--remote-name", "up"]);
    let dest = root.path().join("mirror");
    let export = [
        "git",
        "export",
        dest.to_str().unwrap(),
        "--remote-name",
        "m",
        "--no-attest",
    ];
    kit(&fork, &export);

    for name in ["up", "m"] {
        let mirror = fork.join(".kit/git").join(name).join("repo.git");
        let config = std::fs::read_to_string(mirror.join("config")).unwrap();
        assert!(!config.contains("sshCommand"), "{name}: {config}");
        assert!(!mirror.join("hooks/pre-push").exists(), "{name}");
    }
}

/// With no valid `HEAD` in the mirror, git would search the directories above
/// it for a repository and use that one.
#[test]
fn fetch_refuses_a_mirror_that_git_would_replace_with_a_parent() {
    let f = Fixture::imported();
    let state = f.fork().join(".kit/git/up");
    git(&state, &["init", "--quiet", "--bare", "."]);
    std::fs::write(
        state.join("config"),
        format!(
            "[core]\n\tbare = true\n[remote \"origin\"]\n\turl = {}\n\tuploadpack = touch {}; git-upload-pack\n",
            f.root.path().join("upstream").display(),
            f.marker().display()
        ),
    )
    .unwrap();
    std::fs::remove_file(f.mirror().join("HEAD")).unwrap();
    f.fetch_refuses();
}

/// A mirror whose `refs` directory is a link would make export move the
/// branches of the repository the link names.
#[cfg(unix)]
#[test]
fn export_refuses_a_mirror_whose_refs_is_a_link() {
    let f = Fixture::imported();
    let dest = f.root.path().join("mirror");
    let run = || {
        f.kit(
            &f.fork(),
            &[
                "git",
                "export",
                dest.to_str().unwrap(),
                "--remote-name",
                "m",
                "--no-attest",
            ],
        )
    };
    let out = run();
    assert!(out.status.success(), "{out:?}");

    let other = f.root.path().join("other-refs");
    std::fs::create_dir(&other).unwrap();
    let refs = f.fork().join(".kit/git/m/repo.git/refs");
    std::fs::remove_dir_all(&refs).unwrap();
    std::os::unix::fs::symlink(&other, &refs).unwrap();
    let out = run();
    assert!(!out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refusing the staging mirror"),
        "{out:?}"
    );
    assert_eq!(std::fs::read_dir(&other).unwrap().count(), 0);
}

/// An export into a mirror location that is a link creates nothing in the
/// directory that the link names.
#[cfg(unix)]
#[test]
fn export_creates_nothing_through_a_link_in_place_of_the_mirror() {
    let f = Fixture::imported();
    let other = f.root.path().join("other-dir");
    std::fs::create_dir(&other).unwrap();
    let state = f.fork().join(".kit/git/m");
    std::fs::create_dir_all(&state).unwrap();
    std::os::unix::fs::symlink(&other, state.join("repo.git")).unwrap();
    let dest = f.root.path().join("mirror");
    let out = f.kit(
        &f.fork(),
        &[
            "git",
            "export",
            dest.to_str().unwrap(),
            "--remote-name",
            "m",
            "--no-attest",
        ],
    );
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(std::fs::read_dir(&other).unwrap().count(), 0);
}
