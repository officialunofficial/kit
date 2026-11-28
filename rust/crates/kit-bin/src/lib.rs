#![doc = include_str!("../README.md")]
//!
//! `kit` CLI crate, exposed as a library so integration tests can
//! drive commands in-process.
//!
//! The binary is `src/main.rs`; everything else is a module here so
//! unit tests and integration tests can link without shelling out.
//! `kit-bin` IS published to crates.io so `cargo install kit-bin`
//! works, but its library surface (`kit_bin::…`) is unstable, exists
//! only for in-process testing, and is deliberately excluded from
//! `cargo-semver-checks` — do not depend on it as a stable API.

#![forbid(unsafe_code)]

mod admission_helper;
pub mod clap_args;
pub mod cli;
pub mod commands;
mod completion;
pub mod config;
pub mod editor;
mod environment;
pub mod exit;
pub mod exit_map;
pub mod fd_limit;
pub mod format;
pub mod grants;
pub mod progress;
pub mod remote_dispatch;
mod restore_fanout;
pub mod signal;
#[cfg(feature = "sparse-checkout")]
pub mod sparse_cache;
pub mod term;

use std::io::Write;

/// Dispatch a single argv invocation. Takes the full argv including
/// `argv[0]`. Returns the exit code the binary should pass to
/// `std::process::exit`.
///
/// All I/O goes through stdout/stderr so integration tests either
/// spawn the binary (full end-to-end) or drive this entry point
/// directly (in-process, faster). We keep this function small and
/// dispatch-only so the command modules remain easy to snapshot.
///
/// When the binary called [`signal::enable`], a command that polls the
/// shutdown flag, or runs a multi-step operation, installs the SIGINT and
/// SIGTERM handlers here ([`signal::defers_interrupt`]); every other command
/// keeps the default action. A caller that did not call [`signal::enable`]
/// gets no signal handler.
#[must_use]
pub fn dispatch(argv: &[String]) -> u8 {
    // Consume leading global flags (`-C <path>` and `-c <key>=<val>`) BEFORE
    // resolving the subcommand, so they apply to every command and to repo
    // discovery, like git.
    let (cmd_idx, overrides) = match parse_global_flags(argv) {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    environment::install(environment::from_process(overrides));

    if cmd_idx >= argv.len() {
        print_usage_stderr();
        return exit::USAGE;
    }
    let cmd = &argv[cmd_idx];
    let rest: Vec<String> = argv.iter().skip(cmd_idx + 1).cloned().collect();

    if let Some(code) = run_builtin(cmd, &rest) {
        return code;
    }
    run_alias(cmd, &rest)
}

/// The commands that dispatch runs itself. An alias with one of these names
/// is ignored, so a built-in always wins.
pub const BUILTIN_COMMANDS: &[&str] = &[
    "__complete",
    "help",
    "version",
    "init",
    "key",
    "grant",
    "epoch",
    "visibility",
    "keygen",
    "hash",
    "cat",
    "cat-file",
    "ls-tree",
    "ls-files",
    "rev-parse",
    "show",
    "show-ref",
    "for-each-ref",
    "symbolic-ref",
    "update-ref",
    "ref",
    "tree",
    "add",
    "rm",
    "mv",
    "restore",
    "reset",
    "status",
    "commit",
    "log",
    "reflog",
    "branch",
    "tag",
    "checkout",
    "switch",
    "merge-base",
    "rev-list",
    "clean",
    "diff",
    "prove",
    "verify",
    "verify-proof",
    "attest",
    "verify-attest",
    "closure",
    "trust",
    "config",
    "remote",
    "push",
    "pull",
    "fetch",
    "clone",
    "mcp",
    "merge",
    "cherry-pick",
    "revert",
    "rebase",
    "bisect",
    "rerere",
    "grep",
    "shortlog",
    "range-diff",
    "describe",
    "apply",
    "archive",
    "am",
    "gc",
    "stash",
    "worktree",
    "blame",
    "self",
    "serve",
    "git",
    "sparse-checkout",
];

/// Is `name` a built-in command (or one of its spellings, such as `-h`)?
#[must_use]
pub fn is_builtin(name: &str) -> bool {
    BUILTIN_COMMANDS.contains(&name) || matches!(name, "-h" | "--help" | "--version" | "-V")
}

/// Run built-in command `cmd`, or `None` when there is none of that name.
#[allow(clippy::too_many_lines)] // flat command-dispatch match; splitting it would only hurt readability
fn run_builtin(cmd: &str, rest: &[String]) -> Option<u8> {
    if signal::defers_interrupt(cmd, rest) {
        signal::install();
    }
    let rest = rest.to_vec();
    Some(match cmd {
        "__complete" => completion::run(&rest),
        "-h" | "--help" | "help" => {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(cli::HELP_TEXT.as_bytes());
            exit::OK
        }
        "version" | "--version" | "-V" => {
            let mut stdout = std::io::stdout().lock();
            // Byte-exact `"kit <X.Y.Z>\n"` — pinned by the snapshot
            // test in tests/version_snapshot.rs AND by Homebrew shell
            // asserts. Any refactor that widens this must
            // update docs/CLI.md and ship a 1.0 major bump. The
            // top-level `--version`/`-V` flags are aliases of the
            // `version` subcommand (git-parity) and emit the same
            // canonical string.
            let _ = writeln!(stdout, "kit {}", cli::CLI_VERSION);
            exit::OK
        }
        "init" => commands::init::run(&rest),
        "key" => commands::key::run(&rest),
        "grant" => commands::grant::run(&rest),
        "epoch" => commands::epoch::run(&rest),
        "visibility" => commands::visibility::run(&rest),
        "keygen" => commands::keygen::run(&rest),
        "hash" => commands::hash_cmd::run(&rest),
        "cat" => commands::cat::run(&rest),
        "cat-file" => commands::cat_file::run(&rest),
        "ls-tree" => commands::ls_tree::run(&rest),
        "ls-files" => commands::ls_files::run(&rest),
        "rev-parse" => commands::rev_parse::run(&rest),
        "show" => commands::show::run(&rest),
        "show-ref" => commands::show_ref::run(&rest),
        "for-each-ref" => commands::for_each_ref::run(&rest),
        "symbolic-ref" => commands::symbolic_ref::run(&rest),
        "update-ref" => commands::update_ref::run(&rest),
        "ref" => commands::ref_cmd::run(&rest),
        "tree" => commands::tree::run(&rest),
        "add" => commands::add::run(&rest),
        "rm" => commands::rm::run(&rest),
        "mv" => commands::mv::run(&rest),
        "restore" => commands::restore::run(&rest),
        "reset" => commands::reset::run(&rest),
        "status" => commands::status::run(&rest),
        "commit" => commands::commit::run(&rest),
        "log" => commands::log::run(&rest),
        "reflog" => commands::reflog::run(&rest),
        "branch" => commands::branch::run(&rest),
        "tag" => commands::tag::run(&rest),
        "checkout" => commands::checkout::run(&rest),
        "switch" => commands::switch::run(&rest),
        "merge-base" => commands::merge_base::run(&rest),
        "rev-list" => commands::rev_list::run(&rest),
        "clean" => commands::clean::run(&rest),
        "diff" => commands::diff::run(&rest),
        "prove" => commands::prove::run(&rest),
        "verify" => commands::verify::run(&rest),
        "verify-proof" => commands::verify_proof::run(&rest),
        "attest" => commands::attest::run(&rest),
        "verify-attest" => commands::verify_attest::run(&rest),
        "closure" => commands::closure::run(&rest),
        "trust" => commands::trust::run(&rest),
        "config" => commands::config_cmd::run(&rest),
        "remote" => commands::remote::run(&rest),
        "push" => commands::push::run(&rest),
        "pull" => commands::pull::run(&rest),
        "fetch" => commands::fetch::run(&rest),
        "clone" => commands::clone::run(&rest),
        "mcp" => commands::mcp::run(&rest),
        "merge" => commands::merge::run(&rest),
        "cherry-pick" => commands::cherry_pick::run(&rest),
        "revert" => commands::revert::run(&rest),
        "rebase" => commands::rebase::run(&rest),
        "bisect" => commands::bisect::run(&rest),
        "rerere" => commands::rerere::run(&rest),
        "grep" => commands::grep::run(&rest),
        "shortlog" => commands::shortlog::run(&rest),
        "range-diff" => commands::range_diff::run(&rest),
        "describe" => commands::describe::run(&rest),
        "apply" => commands::apply::run(&rest),
        "archive" => commands::archive::run(&rest),
        "am" => commands::am::run(&rest),
        "gc" => commands::gc::run(&rest),
        "stash" => commands::stash::run(&rest),
        "worktree" => commands::worktree::run(&rest),
        "blame" => commands::blame::run(&rest),
        "self" => commands::self_update::run(&rest),
        "serve" => commands::serve::run(&rest),
        #[cfg(feature = "git-bridge")]
        "git" => commands::git::run(&rest),
        #[cfg(not(feature = "git-bridge"))]
        "git" => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "error: the git bridge is not compiled into this binary; \
                 rebuild with `--features git-bridge` (see docs/specs/SPEC-GIT-BRIDGE.md)"
            );
            exit::UNAVAILABLE
        }
        "sparse-checkout" => commands::sparse_checkout::run(&rest),
        _ => return None,
    })
}

/// Run `cmd` as an alias from the user-scoped config, or report an unknown
/// command. An alias expands once: its first word must be a built-in.
fn run_alias(cmd: &str, rest: &[String]) -> u8 {
    let fail = |msg: &str, code: u8| {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "error: {msg}");
        code
    };
    let unknown = |name: &str| {
        fail(
            &format!("unknown command '{name}' (run 'kit --help' for a list of commands)"),
            exit::USAGE,
        )
    };
    let name = cmd.to_ascii_lowercase();
    if !config::valid_alias_name(&name) {
        return unknown(cmd);
    }
    let aliases = match config::read_user_aliases() {
        Ok(a) => a,
        Err(e) => return fail(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let Some(value) = aliases.get(&name) else {
        return unknown(cmd);
    };
    let words = match config::split_alias(value) {
        Ok(w) => w,
        Err(e) => return fail(&format!("alias '{name}': {e}"), exit::CONFIG_ERROR),
    };
    let Some((first, more)) = words.split_first() else {
        return fail(&format!("alias '{name}' is empty"), exit::USAGE);
    };
    if !is_builtin(first) {
        if aliases.contains_key(&first.to_ascii_lowercase()) {
            return fail(
                &format!(
                    "alias '{name}' expands to the alias '{first}'; aliases do not expand twice"
                ),
                exit::USAGE,
            );
        }
        return fail(
            &format!("alias '{name}' expands to the unknown command '{first}'"),
            exit::USAGE,
        );
    }
    let args: Vec<String> = more.iter().chain(rest).cloned().collect();
    run_builtin(first, &args).unwrap_or(exit::USAGE)
}

/// Consume the leading global flags from `argv` (after `argv[0]`):
/// `-C <path>` / `-C<path>` changes directory (repeatable, relative
/// resolution like git), `-c <key>=<val>` / `-c<key>=<val>` records a
/// one-shot config override. Returns the index of the subcommand token
/// and the collected overrides, or an exit code on a malformed flag or a
/// failed `chdir`.
fn parse_global_flags(argv: &[String]) -> Result<(usize, Vec<(String, String)>), u8> {
    let mut i = 1; // skip argv[0]
    let mut overrides: Vec<(String, String)> = Vec::new();
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "-C" {
            let Some(path) = argv.get(i + 1) else {
                return Err(global_flag_err("option `-C` requires a path"));
            };
            chdir(path)?;
            i += 2;
        } else if let Some(path) = arg.strip_prefix("-C").filter(|p| !p.is_empty()) {
            chdir(path)?;
            i += 1;
        } else if arg == "-c" {
            let Some(kv) = argv.get(i + 1) else {
                return Err(global_flag_err("option `-c` requires <key>=<value>"));
            };
            overrides.push(split_config_override(kv)?);
            i += 2;
        } else if let Some(kv) = arg.strip_prefix("-c").filter(|kv| !kv.is_empty()) {
            overrides.push(split_config_override(kv)?);
            i += 1;
        } else {
            break;
        }
    }
    Ok((i, overrides))
}

/// `chdir` for `-C`, resolving relative paths against the current dir
/// (repeatable `-C` composes, like git).
fn chdir(path: &str) -> Result<(), u8> {
    std::env::set_current_dir(path).map_err(|e| {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "error: cannot change to '{path}': {e}");
        exit::NOINPUT
    })
}

/// Split a `-c key=value` argument; the value may itself contain `=`.
fn split_config_override(kv: &str) -> Result<(String, String), u8> {
    match kv.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => Err(global_flag_err(
            "option `-c` expects <key>=<value> (e.g. -c default_branch=trunk)",
        )),
    }
}

fn global_flag_err(msg: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    exit::USAGE
}

fn print_usage_stderr() {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(cli::HELP_TEXT.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name the dispatch match handles is in [`BUILTIN_COMMANDS`], and
    /// every listed name has an arm, so an alias can never shadow a command.
    #[test]
    fn builtin_list_matches_the_dispatch_arms() {
        let src = include_str!("lib.rs");
        let body = &src[src.find("fn run_builtin").unwrap()..src.find("fn run_alias(").unwrap()];
        let mut arms = std::collections::BTreeSet::new();
        for line in body.lines() {
            let t = line.trim();
            if t.starts_with('"') && t.contains("=>") {
                for part in t.split("=>").next().unwrap().split('|') {
                    let name = part.trim().trim_matches('"');
                    if !name.starts_with('-') {
                        arms.insert(name);
                    }
                }
            }
        }
        let listed: std::collections::BTreeSet<&str> = BUILTIN_COMMANDS.iter().copied().collect();
        assert_eq!(arms, listed);
    }

    #[test]
    fn dispatch_version_returns_ok() {
        // Even without a repo, `version` should succeed.
        let argv = vec!["kit".to_string(), "version".to_string()];
        assert_eq!(dispatch(&argv), exit::OK);
    }

    #[test]
    fn dispatch_unknown_command_returns_usage() {
        let argv = vec!["kit".to_string(), "definitely-not-a-command".to_string()];
        assert_eq!(dispatch(&argv), exit::USAGE);
    }

    #[test]
    fn dispatch_bare_binary_returns_usage() {
        let argv = vec!["kit".to_string()];
        assert_eq!(dispatch(&argv), exit::USAGE);
    }
}
