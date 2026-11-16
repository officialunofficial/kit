//! Honest transfer-progress reporting for `clone`/`push`/`pull`/`fetch`.
//!
//! Driven end-to-end through the real binary against a `kit+file://`
//! bare-directory remote, mirroring `push_named_remote.rs`'s pattern.
//! `KIT_PROGRESS=always` forces progress on despite the subprocess's
//! piped (non-tty) stderr — see `crate::progress`'s override
//! convention (mirrors `NO_COLOR`/`CLICOLOR_FORCE`). The default (no
//! override) is exercised by the suppression test below: a piped
//! stderr with no override must show no progress lines at all.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn kit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_kit")
}

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    run_in_with_env(cwd, args, &[])
}

fn run_in_with_env(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let mut cmd = Command::new(kit_bin());
    cmd.args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn kit");
    drop(xdg);
    out
}

fn file_url(dir: &Path) -> String {
    format!("kit+file://{}", dir.display())
}

/// Init a repo with a signing key and a single commit containing `n`
/// distinct small files — enough objects (n blobs + n path-component
/// trees + 1 commit) to cross the progress reporter's throttling
/// interval (`progress::REPORT_INTERVAL`, currently 8) several times
/// over in one push.
fn repo_with_many_files(n: usize) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    for i in 0..n {
        fs::write(td.path().join(format!("f{i}.txt")), format!("file {i}")).unwrap();
    }
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "many files"])
            .status
            .success()
    );
    td
}

/// Push, forcing progress on via `KIT_PROGRESS=always` (the
/// subprocess's stderr is piped, not a tty, so without the override
/// the reporter would auto-disable): must print multiple `Writing
/// objects:` lines with monotonically increasing, real object counts,
/// ending in a `, done.` line — never git's
/// Enumerating/Counting/Compressing/delta lines.
#[test]
fn push_reports_honest_monotonic_progress_when_forced_on() {
    let td = repo_with_many_files(40);
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );

    let out = run_in_with_env(
        td.path(),
        &["push", "origin"],
        &[("KIT_PROGRESS", "always")],
    );
    assert!(out.status.success(), "push failed: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();

    let counts = extract_counts(&stderr, "Writing objects");
    assert!(
        counts.len() >= 2,
        "expected multiple progress updates crossing the report threshold, got stderr: {stderr}"
    );
    assert!(
        counts.windows(2).all(|w| w[0] <= w[1]),
        "counts must be monotonically non-decreasing: {counts:?} (stderr: {stderr})"
    );
    assert!(
        *counts.last().unwrap() > 0,
        "final count must reflect real objects sent: {counts:?}"
    );
    assert!(stderr.contains("done."), "{stderr}");
    assert!(!stderr.contains("bytes objects"), "{stderr}");
    // kit does not print git's count and delta lines (docs/CLI.md).
    assert!(!stderr.contains("Compressing objects"), "stderr: {stderr}");
    assert!(!stderr.contains("Enumerating objects"), "stderr: {stderr}");
    assert!(!stderr.contains("Total "), "stderr: {stderr}");
}

/// Without an explicit override, a non-tty stderr (the default for a
/// piped subprocess, as in every test here) must show NO progress
/// lines — exercising `should_report`'s tty auto-detection, not
/// `--quiet`.
#[test]
fn push_suppresses_progress_by_default_on_non_tty_stderr() {
    let td = repo_with_many_files(40);
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );

    let out = run_in(td.path(), &["push", "origin"]);
    assert!(out.status.success(), "push failed: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("Writing objects"),
        "progress must be suppressed on non-tty stderr by default: {stderr}"
    );
    // The ordinary git-shaped summary must still print.
    assert!(stderr.contains("To "), "stderr: {stderr}");
}

/// `--quiet` suppresses progress even when `KIT_PROGRESS=always` would
/// otherwise force it on — the explicit flag wins.
#[test]
fn push_quiet_flag_wins_over_forced_progress() {
    let td = repo_with_many_files(10);
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );

    let out = run_in_with_env(
        td.path(),
        &["push", "origin", "--quiet"],
        &[("KIT_PROGRESS", "always")],
    );
    assert!(out.status.success(), "push failed: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("Writing objects"),
        "--quiet must suppress progress even under KIT_PROGRESS=always: {stderr}"
    );
}

/// Fetch/pull side: push several small commits separately (building a
/// multi-node packmap chain), then a fresh `clone` must unpack each
/// chain pack in turn and report real, monotonically increasing
/// `Unpacking objects:` counts across the packs it applies.
#[test]
fn clone_reports_honest_monotonic_progress_across_chain_packs_when_forced_on() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );

    // Several separate pushes chain multiple packmap nodes, so the
    // subsequent clone below applies more than one pack and reports
    // more than one real `ObjectsUnpacked` event.
    for i in 0..5 {
        fs::write(td.path().join(format!("g{i}.txt")), format!("gen {i}")).unwrap();
        assert!(run_in(td.path(), &["add", "."]).status.success());
        assert!(
            run_in(td.path(), &["commit", "-m", &format!("gen {i}")])
                .status
                .success()
        );
        assert!(
            run_in(td.path(), &["push", "origin"]).status.success(),
            "push gen {i}"
        );
    }

    let dst = tempfile::tempdir().unwrap();
    let clone_dir = dst.path().join("clone");
    let out = run_in_with_env(
        dst.path(),
        &["clone", &url, clone_dir.to_str().unwrap()],
        &[("KIT_PROGRESS", "always")],
    );
    assert!(out.status.success(), "clone failed: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();

    let counts = extract_counts(&stderr, "Unpacking objects");
    assert!(
        counts.len() >= 2,
        "expected progress across multiple chain packs, got stderr: {stderr}"
    );
    assert!(
        counts.windows(2).all(|w| w[0] <= w[1]),
        "counts must be monotonically non-decreasing: {counts:?} (stderr: {stderr})"
    );
}

/// Parse every `"<label>: N ..."` occurrence out of a progress stream,
/// in order, returning just the `N` values. Progress lines
/// self-overwrite with `\r`, so this splits on `\r` as well as `\n`.
fn extract_counts(stderr: &str, label: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for line in stderr.split(['\r', '\n']) {
        let Some(rest) = line.strip_prefix(label) else {
            continue;
        };
        let rest = rest.trim_start_matches(':').trim_start();
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(n) = digits.parse::<u64>() {
            out.push(n);
        }
    }
    out
}

#[test]
fn clone_json_progress_reports_download_lengths_and_restored_files() {
    let source = repo_with_many_files(40);
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(source.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    assert!(run_in(source.path(), &["push", "origin"]).status.success());
    let dest = tempfile::tempdir().unwrap();
    let out = run_in_with_env(
        dest.path(),
        &["clone", &url, "clone"],
        &[("KIT_PROGRESS", "json")],
    );
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains('\r'));
    let rows: Vec<serde_json::Value> = stderr
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| serde_json::from_str(line).expect("progress JSON"))
        .collect();
    assert!(!rows.is_empty(), "{stderr}");
    for row in &rows {
        assert!(row["phase"].is_string());
        for key in ["done", "bytes", "elapsed_ms"] {
            assert!(row[key].is_u64(), "{row}");
        }
        for key in ["total", "bytes_total"] {
            assert!(row[key].is_null() || row[key].is_u64(), "{row}");
        }
    }
    assert!(rows.iter().any(|r| r["phase"] == "download"
        && r["bytes"].as_u64().unwrap() > 0
        && r["bytes"] == r["bytes_total"]));
    assert!(
        rows.iter()
            .any(|r| r["phase"] == "restore" && r["done"] == 40 && r["total"] == 40)
    );
}

#[test]
fn local_progress_is_opt_in_when_stderr_is_piped() {
    let repo = repo_with_many_files(2);
    fs::write(repo.path().join("new"), "content").unwrap();
    let plain = run_in_with_env(repo.path(), &["add", "new"], &[("KIT_PROGRESS", "auto")]);
    assert!(plain.status.success());
    assert!(plain.stderr.is_empty(), "{plain:?}");
    fs::write(repo.path().join("new"), "more content").unwrap();
    let json = run_in_with_env(repo.path(), &["add", "new"], &[("KIT_PROGRESS", "json")]);
    assert!(json.status.success());
    let rows: Vec<serde_json::Value> = String::from_utf8(json.stderr)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(rows.iter().any(|r| r["phase"] == "add" && r["bytes"] == 12));
    let gc = run_in_with_env(repo.path(), &["gc", "-n"], &[("KIT_PROGRESS", "json")]);
    assert!(gc.status.success());
    assert!(
        String::from_utf8(gc.stderr)
            .unwrap()
            .lines()
            .filter(|l| l.starts_with('{'))
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .any(|r| r["phase"] == "gc" && r["done"].as_u64().unwrap() > 0)
    );
}

#[cfg(unix)]
#[test]
#[ignore = "clones 1 GiB over kit+file; run in release mode"]
fn one_gib_clone_reports_download_bytes_at_least_every_two_seconds() {
    use std::io::{Read, Write};
    let source = repo_with_many_files(1);
    let mut random = fs::File::open("/dev/urandom").unwrap();
    let mut data = fs::File::create(source.path().join("data")).unwrap();
    let mut buffer = vec![0u8; 1 << 20];
    for _ in 0..1024 {
        random.read_exact(&mut buffer).unwrap();
        data.write_all(&buffer).unwrap();
    }
    drop(data);
    assert!(run_in(source.path(), &["add", "data"]).status.success());
    assert!(
        run_in(source.path(), &["commit", "-m", "data"])
            .status
            .success()
    );
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(source.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );
    assert!(run_in(source.path(), &["push", "origin"]).status.success());
    let dest = tempfile::tempdir().unwrap();
    let out = run_in_with_env(
        dest.path(),
        &["clone", &url, "clone"],
        &[("KIT_PROGRESS", "json")],
    );
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    let mut last = None;
    let mut updates = 0;
    let mut declared = false;
    for line in stderr.lines().filter(|l| l.starts_with('{')) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        if row["phase"] != "download" {
            last = None;
            continue;
        }
        let elapsed = row["elapsed_ms"].as_u64().unwrap();
        if row["bytes"] == 0 {
            last = Some(elapsed);
            continue;
        }
        if let Some(previous) = last {
            assert!(
                elapsed.saturating_sub(previous) <= 2000,
                "download stalled between records: {row}"
            );
        }
        last = Some(elapsed);
        updates += 1;
        declared |= row["bytes_total"].as_u64().is_some_and(|total| total > 0);
    }
    assert!(updates >= 4);
    assert!(declared);
}

#[test]
fn dry_run_results_start_after_the_progress_line() {
    let repo = repo_with_many_files(1);
    fs::write(repo.path().join("fresh"), "new").unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let log = tempfile::NamedTempFile::new().unwrap();
    let merged = log.as_file().try_clone().unwrap();
    let status = Command::new(kit_bin())
        .args(["add", "-n", "fresh"])
        .current_dir(repo.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("KIT_PROGRESS", "always")
        .stdout(merged.try_clone().unwrap())
        .stderr(merged)
        .status()
        .unwrap();
    assert!(status.success());
    let text = fs::read_to_string(log.path()).unwrap();
    assert!(text.contains("\nadd 'fresh'\n"), "{text}");
    assert!(text.ends_with("add 'fresh'\n"), "{text}");
}

#[test]
fn tracked_file_updates_report_hashed_input_bytes() {
    let repo = repo_with_many_files(1);
    let content = "updated tracked content";
    fs::write(repo.path().join("f0.txt"), content).unwrap();
    let out = run_in_with_env(repo.path(), &["add", "-u"], &[("KIT_PROGRESS", "json")]);
    assert!(out.status.success(), "{out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    let rows: Vec<serde_json::Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(rows.iter().any(|row| {
        row["phase"] == "add" && row["bytes"].as_u64() == Some(content.len() as u64)
    }));
}
