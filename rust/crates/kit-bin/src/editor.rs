//! `$EDITOR` / `$VISUAL` spawn helper for `kit commit`, `kit tag -a` and
//! `kit rebase -i`.
//!
//! Behaviour:
//! * Honour `$GIT_EDITOR` first, then `$EDITOR`, then `$VISUAL`.
//! * Fall back to `vi` when no env var is set, so `kit commit` works
//!   out-of-the-box.
//! * An editor the user set is always started, terminal or not, as git
//!   does: `EDITOR="code --wait"` works from a script.
//! * Start no editor when none is set and stdin is not a terminal: the
//!   default `vi` would wait for a terminal that never comes.
//! * Write `template` to a tempfile, spawn the editor, wait, read the
//!   file back, strip any line whose first non-whitespace byte is `#`,
//!   and return the trimmed message.

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::Command;

/// Maximum commit-message file size read back from the editor (1 MiB).
pub const MAX_COMMIT_MSG_BYTES: u64 = 1024 * 1024;

/// Spawn the user's editor on a tempfile pre-populated with `template`,
/// then read the file back, strip `#`-comment lines, and return the
/// trimmed result.
///
/// The editor is chosen in this order:
/// 1. `$GIT_EDITOR`
/// 2. `$EDITOR`
/// 3. `$VISUAL`
/// 4. platform default (`vi`)
///
/// The editor invocation parses the chosen value as a shell-like
/// command: the first whitespace-separated token is the program, the
/// rest are arguments, and the tempfile path is appended as a final
/// argument. This matches how `git`'s `GIT_EDITOR` is conventionally
/// parsed (e.g. `EDITOR="vim -c 'set nowrap'"`).
///
/// # Errors
/// - [`check_usable`]'s error when no editor is set and stdin is not a
///   terminal.
/// - [`io::ErrorKind::NotFound`] if the editor binary cannot be spawned.
/// - [`io::ErrorKind::Other`] with a descriptive message if the editor
///   exits non-zero or the file exceeds [`MAX_COMMIT_MSG_BYTES`].
pub fn spawn_editor(template: &str) -> io::Result<String> {
    check_usable()?;
    let editor = pick_editor();
    if editor.is_empty() {
        return Err(io::Error::other(
            "no editor configured; set $EDITOR or pass -m <msg>",
        ));
    }

    // Write template to a tempfile. We use `tempfile` to get a
    // predictable cleanup path — the file's dropped when `file` goes
    // out of scope even if the editor crashed.
    let tmp = tempfile::NamedTempFile::with_suffix(".kit-commit.txt")?;
    {
        let mut f = fs::OpenOptions::new().write(true).open(tmp.path())?;
        f.write_all(template.as_bytes())?;
        f.sync_all()?;
    }

    // Parse the editor string into [program, args...] and append the
    // tempfile path. Whitespace-split is intentionally crude — quoted
    // arguments with embedded whitespace are rare in practice and
    // require a full shell to handle correctly. The test suite uses
    // the simple `sh -c '…' sh` idiom which works under this split.
    let mut parts = editor.split_whitespace();
    let program = parts.next().unwrap_or("");
    let extra_args: Vec<&str> = parts.collect();
    let path_arg: PathBuf = tmp.path().to_path_buf();

    let status = crate::signal::while_editor_runs(|| {
        Command::new(program)
            .args(&extra_args)
            .arg(&path_arg)
            .status()
    })?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "editor exited with status {status:?}"
        )));
    }

    // Read the file back. Bounded to MAX_COMMIT_MSG_BYTES.
    let f = fs::File::open(tmp.path())?;
    let mut buf = Vec::new();
    f.take(MAX_COMMIT_MSG_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(io::Error::other)?;
    if buf.len() as u64 > MAX_COMMIT_MSG_BYTES {
        return Err(io::Error::other("commit message file too large (>1 MiB)"));
    }
    let raw = String::from_utf8_lossy(&buf).into_owned();
    Ok(strip_comments_and_trim(&raw))
}

/// The error of [`check_usable`] when it refuses.
#[derive(Debug)]
struct NoTerminal;

impl std::fmt::Display for NoTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "no editor is set and stdin is not a terminal, so none was started; \
             set GIT_EDITOR, EDITOR or VISUAL",
        )
    }
}

impl std::error::Error for NoTerminal {}

/// Whether `error` is [`check_usable`]'s refusal, a usage error.
#[must_use]
pub fn is_no_terminal(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<NoTerminal>)
}

/// Refuse to start the default editor when stdin is not a terminal. An
/// editor the user set is never refused. Call it before any work that a
/// refused editor would waste.
///
/// # Errors
/// An [`io::ErrorKind::Other`] error that says why and what to do instead.
pub fn check_usable() -> io::Result<()> {
    check_usable_with(io::stdin().is_terminal(), |name| std::env::var(name).ok())
}

/// [`check_usable`] with the terminal test and the environment passed in.
fn check_usable_with(
    stdin_is_terminal: bool,
    resolver: impl Fn(&str) -> Option<String>,
) -> io::Result<()> {
    if stdin_is_terminal || set_editor_with(resolver).is_some() {
        Ok(())
    } else {
        Err(io::Error::other(NoTerminal))
    }
}

/// Pick an editor from the environment. Returns an empty string if
/// nothing usable is set AND no platform default applies.
fn pick_editor() -> String {
    pick_editor_with(|name| std::env::var(name).ok())
}

/// Test-friendly variant of [`pick_editor`]: the editor the user set, or
/// the platform default (`vi`) when none is set.
fn pick_editor_with(resolver: impl Fn(&str) -> Option<String>) -> String {
    set_editor_with(resolver).unwrap_or_else(|| "vi".to_string())
}

/// The editor the user set: `resolver` is called once per candidate env
/// var, and the first value that is not blank wins.
fn set_editor_with(resolver: impl Fn(&str) -> Option<String>) -> Option<String> {
    ["GIT_EDITOR", "EDITOR", "VISUAL"]
        .into_iter()
        .find_map(|var| resolver(var).filter(|v| !v.trim().is_empty()))
}

/// Strip all lines whose first non-whitespace byte is `#`, then trim
/// trailing whitespace.
#[must_use]
pub fn strip_comments_and_trim(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.split('\n') {
        let first_nws = line.trim_start();
        if first_nws.starts_with('#') {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n')
        .to_string()
}

/// Template rendered into the tempfile before spawning the editor.
pub const COMMIT_EDITMSG_TEMPLATE: &str = "\n\
# Please enter the commit message for your changes. Lines starting\n\
# with '#' will be ignored, and an empty message aborts the commit.\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_comments_drops_hash_lines() {
        let input = "\nhello\n# a comment\nworld\n   # indented comment\n\n";
        let out = strip_comments_and_trim(input);
        assert_eq!(out, "hello\nworld");
    }

    #[test]
    fn strip_comments_all_comment_yields_empty() {
        let out = strip_comments_and_trim("# foo\n# bar\n");
        assert!(out.is_empty());
    }

    #[test]
    fn strip_comments_trims_trailing_crlf() {
        let out = strip_comments_and_trim("hello\r\n# drop\r\n\r\n");
        assert_eq!(out, "hello");
    }

    #[test]
    fn pick_editor_prefers_git_editor_over_editor() {
        let got = pick_editor_with(|name| match name {
            "GIT_EDITOR" => Some("from-git".to_string()),
            "EDITOR" => Some("from-editor".to_string()),
            _ => None,
        });
        assert_eq!(got, "from-git");
    }

    #[test]
    fn pick_editor_prefers_editor_over_visual() {
        let got = pick_editor_with(|name| match name {
            "EDITOR" => Some("from-editor".to_string()),
            "VISUAL" => Some("from-visual".to_string()),
            _ => None,
        });
        assert_eq!(got, "from-editor");
    }

    #[test]
    fn pick_editor_skips_empty_strings() {
        let got = pick_editor_with(|name| match name {
            "GIT_EDITOR" => Some(String::new()),
            "EDITOR" => Some("   ".to_string()),
            "VISUAL" => Some("nano".to_string()),
            _ => None,
        });
        assert_eq!(got, "nano");
    }

    #[test]
    fn no_terminal_refuses_only_the_default_editor() {
        assert!(check_usable_with(true, |_| None).is_ok());
        assert!(check_usable_with(false, |_| None).is_err_and(|e| is_no_terminal(&e)));
        assert!(!is_no_terminal(&io::Error::other("other")));
        let only =
            |var: &'static str| move |name: &str| (name == var).then(|| "my-editor".to_string());
        for var in ["GIT_EDITOR", "EDITOR", "VISUAL"] {
            assert!(check_usable_with(false, only(var)).is_ok(), "{var}");
        }
        assert!(check_usable_with(false, |_| Some("  ".to_string())).is_err());
    }

    #[test]
    fn pick_editor_falls_back_to_platform_default() {
        let got = pick_editor_with(|_| None);
        assert_eq!(got, "vi");
    }
}
