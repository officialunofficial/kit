//! `kit archive`: export the tree of a revision as a tar or tar.gz file,
//! for release builds.
//!
//! Fixed cases pin the round trip of a tree with a symlink, an executable
//! and a chunked file, the header fields, the pax global header that holds
//! the commit id, `--prefix`, path limits, the format choice and the usage
//! errors. The system `tar` must list the archive, and two runs under two
//! time zones must give the same bytes. A property test checks the round
//! trip and the path limit on random trees.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

use common::Repo;
use proptest::prelude::*;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// One entry of an archive: its kind, mode and content (the target of a
/// symlink).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    kind: char,
    mode: u32,
    data: Vec<u8>,
}

/// The entries of a tar archive by path, without the pax global header,
/// and the header itself when there is one.
fn read_tar(bytes: &[u8]) -> (BTreeMap<String, Item>, Option<String>) {
    let mut archive = tar::Archive::new(bytes);
    let mut items = BTreeMap::new();
    let mut global = None;
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let header = entry.header().clone();
        let kind = match header.entry_type() {
            tar::EntryType::XGlobalHeader => {
                let mut text = String::new();
                entry.read_to_string(&mut text).unwrap();
                global = Some(text);
                continue;
            }
            tar::EntryType::Directory => 'd',
            tar::EntryType::Symlink => 'l',
            tar::EntryType::Regular => 'f',
            other => panic!("unexpected entry type {other:?}"),
        };
        assert_eq!(header.uid().unwrap(), 0);
        assert_eq!(header.gid().unwrap(), 0);
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        let data = if kind == 'l' {
            entry
                .link_name()
                .unwrap()
                .unwrap()
                .to_string_lossy()
                .into_owned()
                .into_bytes()
        } else {
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            data
        };
        items.insert(
            path,
            Item {
                kind,
                mode: header.mode().unwrap() & 0o7777,
                data,
            },
        );
    }
    (items, global)
}

/// The files of the tree of `rev`, from `kit ls-tree -r`, as archive items
/// read from the worktree, which holds the same content.
fn tree_items(repo: &Repo, rev: &str) -> BTreeMap<String, Item> {
    let listing = stdout(&repo.ok(&["ls-tree", "-r", "-z", rev]));
    let mut items = BTreeMap::new();
    for record in listing.split('\0').filter(|r| !r.is_empty()) {
        let (meta, path) = record.split_once('\t').unwrap();
        let mode = meta.split(' ').next().unwrap();
        let abs = repo.path().join(path);
        let item = match mode {
            "120000" => Item {
                kind: 'l',
                mode: 0o777,
                data: std::fs::read_link(&abs)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes(),
            },
            "100755" => Item {
                kind: 'f',
                mode: 0o755,
                data: std::fs::read(&abs).unwrap(),
            },
            _ => Item {
                kind: 'f',
                mode: 0o644,
                data: std::fs::read(&abs).unwrap(),
            },
        };
        items.insert(path.to_owned(), item);
    }
    items
}

/// Only the files and symlinks of `items`.
fn files(items: &BTreeMap<String, Item>) -> BTreeMap<String, Item> {
    items
        .iter()
        .filter(|(_, i)| i.kind != 'd')
        .map(|(p, i)| (p.clone(), i.clone()))
        .collect()
}

/// A big file, over the chunking threshold, with varied content.
fn big() -> Vec<u8> {
    (0u32..(3 << 19))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13).to_le_bytes()[0])
        .collect()
}

/// A tree with a symlink, an executable, a chunked file and a subdirectory.
fn sample() -> Repo {
    let repo = Repo::new();
    repo.write("README", b"read me\n");
    repo.write("bin/run.sh", b"#!/bin/sh\necho hi\n");
    std::fs::set_permissions(
        repo.path().join("bin/run.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    repo.write("data/big.bin", &big());
    repo.write("data/small.txt", b"small\n");
    std::os::unix::fs::symlink("data/small.txt", repo.path().join("link")).unwrap();
    repo.ok(&[
        "add",
        "README",
        "bin/run.sh",
        "data/big.bin",
        "data/small.txt",
        "link",
    ]);
    repo.ok(&["commit", "-m", "sample"]);
    repo
}

fn archive(repo: &Repo, args: &[&str]) -> Vec<u8> {
    let mut all = vec!["archive"];
    all.extend_from_slice(args);
    repo.ok(&all).stdout
}

fn head(repo: &Repo) -> String {
    stdout(&repo.ok(&["rev-parse", "HEAD"])).trim().to_owned()
}

#[test]
fn a_tar_round_trips_the_tree() {
    let repo = sample();
    let (items, _) = read_tar(&archive(&repo, &["HEAD"]));
    assert_eq!(files(&items), tree_items(&repo, "HEAD"));
    // Directories come as entries too, before what they hold.
    assert_eq!(items["bin/"].kind, 'd');
    assert_eq!(items["data/"].mode, 0o755);
}

#[test]
fn headers_carry_the_commit_time_and_id() {
    let repo = sample();
    let bytes = archive(&repo, &["HEAD"]);
    let (_, global) = read_tar(&bytes);
    let id = head(&repo);
    assert_eq!(
        global.as_deref(),
        Some(format!("76 comment={id}\n").as_str())
    );
    let log = stdout(&repo.ok(&["log", "--format=json", "-n", "1"]));
    let time: u64 = log
        .split("\"timestamp\":")
        .nth(1)
        .unwrap()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut archive = tar::Archive::new(bytes.as_slice());
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        if entry.header().entry_type() != tar::EntryType::XGlobalHeader {
            assert_eq!(entry.header().mtime().unwrap(), time);
        }
    }
    // The archive fills whole tar records of 10240 bytes, as git's does.
    assert_eq!(bytes.len() % 10240, 0);
}

#[test]
fn tar_gz_is_chosen_by_flag_or_by_extension() {
    let repo = sample();
    let want = tree_items(&repo, "HEAD");
    let gz = archive(&repo, &["--format=tar.gz", "HEAD"]);
    let mut tar_bytes = Vec::new();
    flate2::read::GzDecoder::new(gz.as_slice())
        .read_to_end(&mut tar_bytes)
        .unwrap();
    assert_eq!(files(&read_tar(&tar_bytes).0), want);
    for name in ["out.tar.gz", "out.tgz"] {
        let path = repo.path().join(name);
        repo.ok(&["archive", "-o", path.to_str().unwrap(), "HEAD"]);
        let file = std::fs::read(&path).unwrap();
        assert_eq!(file, gz, "{name}");
    }
    let path = repo.path().join("out.tar");
    repo.ok(&["archive", "-o", path.to_str().unwrap(), "HEAD"]);
    assert_eq!(std::fs::read(&path).unwrap(), archive(&repo, &["HEAD"]));
}

#[test]
fn output_is_the_same_bytes_across_runs_and_time_zones() {
    let repo = sample();
    let a = repo.ok_env(&["archive", "--format=tar.gz", "HEAD"], &[("TZ", "UTC")]);
    let b = repo.ok_env(
        &["archive", "--format=tar.gz", "HEAD"],
        &[("TZ", "Asia/Kolkata")],
    );
    assert_eq!(a.stdout, b.stdout);
    let c = repo.ok_env(&["archive", "HEAD"], &[("TZ", "America/New_York")]);
    assert_eq!(c.stdout, archive(&repo, &["HEAD"]));
}

#[test]
fn prefix_and_paths_shape_the_entries() {
    let repo = sample();
    let (items, _) = read_tar(&archive(&repo, &["--prefix=pkg-1.0/", "HEAD"]));
    assert!(items.contains_key("pkg-1.0/"));
    assert!(items.keys().all(|p| p.starts_with("pkg-1.0/")), "{items:?}");
    assert_eq!(items["pkg-1.0/README"].data, b"read me\n");
    let (items, _) = read_tar(&archive(&repo, &["HEAD", "data", "README"]));
    assert_eq!(
        items.keys().cloned().collect::<Vec<_>>(),
        ["README", "data/", "data/big.bin", "data/small.txt"]
    );
}

#[test]
fn only_the_tree_is_read_not_the_worktree() {
    let repo = sample();
    let before = archive(&repo, &["HEAD"]);
    repo.write("README", b"edited\n");
    repo.write("untracked.txt", b"x\n");
    assert_eq!(archive(&repo, &["HEAD"]), before);
}

#[test]
fn a_tree_id_archives_without_a_commit_header() {
    let repo = sample();
    let log = stdout(&repo.ok(&["log", "--format=json", "-n", "1"]));
    let tree = log
        .split("\"tree\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let (items, global) = read_tar(&archive(&repo, &[tree]));
    assert_eq!(global, None);
    assert_eq!(files(&items), tree_items(&repo, "HEAD"));
}

#[test]
fn the_system_tar_lists_the_archive() {
    let Ok(probe) = Command::new("tar").arg("--version").output() else {
        return;
    };
    if !probe.status.success() {
        return;
    }
    let repo = sample();
    let path = repo.path().join("x.tar");
    repo.ok(&[
        "archive",
        "--prefix=p/",
        "-o",
        path.to_str().unwrap(),
        "HEAD",
    ]);
    let out = Command::new("tar").arg("-tf").arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let mut names: Vec<String> = stdout(&out).lines().map(str::to_owned).collect();
    names.retain(|n| n != "pax_global_header");
    assert_eq!(
        names,
        [
            "p/",
            "p/README",
            "p/bin/",
            "p/bin/run.sh",
            "p/data/",
            "p/data/big.bin",
            "p/data/small.txt",
            "p/link",
        ]
    );
}

#[test]
fn usage_errors_exit_64() {
    let repo = sample();
    for args in [
        &["archive"][..],
        &["archive", "--format=zip", "HEAD"],
        &["archive", "-o", "out.rar", "HEAD"],
        &["archive", "--prefix=../up/", "HEAD"],
        &["archive", "--prefix=/abs/", "HEAD"],
        &["archive", "HEAD", "no-such-path"],
        &["archive", "no-such-rev"],
    ] {
        let out = repo.run(args);
        assert_eq!(out.status.code(), Some(64), "{args:?}: {}", stderr(&out));
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    /// On random trees: the archive holds exactly the files and modes of
    /// the tree, and with a path, exactly the files under it.
    #[test]
    fn round_trip_and_path_limit(
        entries in proptest::collection::btree_map(
            ("(a|b|c)/[x-z]{1,3}|[x-z]{1,3}", any::<bool>()),
            proptest::collection::vec(any::<u8>(), 0..64),
            1..8,
        ),
    ) {
        let repo = Repo::new();
        let mut names = Vec::new();
        for ((name, exec), body) in &entries {
            // A name that is both a file and a directory cannot be added.
            if names.iter().any(|n: &String| n.starts_with(&format!("{name}/")) || name.starts_with(&format!("{n}/")) || n == name) {
                continue;
            }
            repo.write(name, body);
            if *exec {
                std::fs::set_permissions(repo.path().join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            names.push(name.clone());
        }
        let mut add = vec!["add"];
        add.extend(names.iter().map(String::as_str));
        repo.ok(&add);
        repo.ok(&["commit", "-m", "random"]);
        let want = tree_items(&repo, "HEAD");
        let (items, _) = read_tar(&archive(&repo, &["HEAD"]));
        prop_assert_eq!(files(&items), want.clone());
        if names.iter().any(|n| n.starts_with("a/")) {
            let (limited, _) = read_tar(&archive(&repo, &["HEAD", "a"]));
            let under: BTreeMap<String, Item> = want
                .into_iter()
                .filter(|(p, _)| p.starts_with("a/"))
                .collect();
            prop_assert_eq!(files(&limited), under);
        }
    }
}

#[test]
fn long_paths_and_link_targets_round_trip() {
    let repo = Repo::new();
    let deep = format!("{}/{}", "d".repeat(120), "f".repeat(60));
    let long_name = "n".repeat(140);
    repo.write(&deep, b"deep\n");
    repo.write(&long_name, b"long\n");
    std::os::unix::fs::symlink(&deep, repo.path().join("to-deep")).unwrap();
    repo.ok(&["add", &deep, &long_name, "to-deep"]);
    repo.ok(&["commit", "-m", "long"]);
    let (items, _) = read_tar(&archive(&repo, &["HEAD"]));
    assert_eq!(files(&items), tree_items(&repo, "HEAD"));
    assert!(items.contains_key(&format!("{}/", "d".repeat(120))));
}
