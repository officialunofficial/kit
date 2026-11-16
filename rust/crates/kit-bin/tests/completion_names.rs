//! Completion reads names without opening objects or contacting remotes.
#![allow(clippy::unwrap_used)]
use std::process::Command;

#[test]
fn completion_is_silent_outside_a_repo_and_lists_only_the_requested_names() {
    let dir = tempfile::tempdir().unwrap();
    let kit = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_kit"))
            .args(args)
            .current_dir(dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("xdg"))
            .output()
            .unwrap()
    };
    let outside = kit(&["__complete", "switch"]);
    assert!(outside.status.success());
    assert!(outside.stdout.is_empty() && outside.stderr.is_empty());
    assert!(kit(&["init"]).status.success());
    for (namespace, name) in [
        ("heads", "topic"),
        ("tags", "v1"),
        ("remotes/origin", "upstream"),
    ] {
        let refs = dir.path().join(".kit/refs").join(namespace);
        std::fs::create_dir_all(&refs).unwrap();
        std::fs::write(refs.join(name), format!("{}\n", "ab".repeat(32))).unwrap();
    }
    assert!(
        kit(&[
            "remote",
            "add",
            "origin",
            "kit+s3://unreachable.invalid/bucket"
        ])
        .status
        .success()
    );
    for (args, expected) in [
        (vec!["switch"], "topic\n"),
        (vec!["checkout"], "topic\n"),
        (vec!["branch", "-d"], "topic\n"),
        (vec!["branch", "-m"], "topic\n"),
        (vec!["branch", "--rename"], "topic\n"),
        (vec!["-C", ".", "switch"], "topic\n"),
        (vec!["merge"], "topic\n"),
        (vec!["rebase"], "topic\n"),
        (vec!["push"], "origin\n"),
        (vec!["fetch", "--all"], ""),
        (vec!["pull", "--all"], ""),
        (vec!["push", "origin"], "topic\n"),
        (vec!["push", "--all", "origin"], ""),
        (vec!["push", "--tags", "origin"], ""),
        (vec!["fetch", "origin"], ""),
        (vec!["pull", "origin"], ""),
        (vec!["remote", "remove"], "origin\n"),
        (vec!["remote", "rename"], "origin\n"),
        (vec!["tag", "-d"], "v1\n"),
        (vec!["tag", "-d", "v1"], ""),
        (vec!["branch", "-d", "topic"], ""),
        (vec!["branch", "-m", "topic"], ""),
        (vec!["switch", "-c"], ""),
        (vec!["switch", "-c", "new"], "topic\n"),
        (vec!["merge", "-m", "message"], "topic\n"),
        (vec!["rebase", "--onto", "base", "upstream"], "topic\n"),
        (vec!["merge", "-m"], ""),
        (vec!["remote", "rename", "origin"], ""),
    ] {
        let mut full = vec!["__complete"];
        full.extend(args);
        let output = kit(&full);
        assert!(
            output.status.success() && output.stderr.is_empty(),
            "{full:?}: {output:?}"
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            expected,
            "{full:?}"
        );
    }
}

#[test]
fn bash_and_zsh_request_the_same_local_names() {
    let dir = tempfile::tempdir().unwrap();
    let refs = dir.path().join(".kit/refs/heads");
    std::fs::create_dir_all(&refs).unwrap();
    std::fs::write(refs.join("topic"), format!("{}\n", "ab".repeat(32))).unwrap();
    let completions = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../completions");
    let path = format!(
        "{}:{}",
        std::path::Path::new(env!("CARGO_BIN_EXE_kit"))
            .parent()
            .unwrap()
            .display(),
        std::env::var("PATH").unwrap_or_default()
    );
    for (shell, script) in [
        (
            "bash",
            "source \"$1/kit.bash\"; _init_completion() { words=(kit switch to); cword=2; cur=to; }; _kit_complete; printf '%s\\n' \"${COMPREPLY[@]}\"",
        ),
        (
            "zsh",
            "compdef() { :; }; compadd() { print -rl -- $names; }; source \"$1/kit.zsh\"; words=(kit switch to); CURRENT=3; PREFIX=to; _kit",
        ),
    ] {
        let result = Command::new(shell)
            .args(["-c", script, "test"])
            .arg(&completions)
            .current_dir(dir.path())
            .env("PATH", &path)
            .output();
        let output = match result {
            Ok(output) => output,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("{shell} unavailable");
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        assert!(output.status.success(), "{shell}: {output:?}");
        assert_eq!(output.stdout, b"topic\n", "{shell}: {output:?}");
    }
}
