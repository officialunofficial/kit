//! Honest transfer-progress reporting for `clone`/`push`/`pull`/`fetch`.
//!
//! `kit clone`/`push`/`pull`/`fetch` print real, already-happened work while
//! a transfer runs: objects staged into the outgoing pack, bytes handed to
//! the transport, and objects unpacked from a downloaded pack.
//!
//! It deliberately never reports git's fabricated
//! `Enumerating/Counting/Compressing objects` or `Total N (delta D)`
//! lines — kit's transport is one-object-per-pack and computes no
//! cross-branch delta graph, so those numbers would be invented (see
//! `docs/CLI.md`).
//!
//! ## The terminal observer
//!
//! [`Terminal`] is the CLI's [`Observer`] for the sync engine. The sync
//! engine delivers each [`SyncEvent`] to it. It prints the progress line, the
//! step lines and the warnings. It also receives the Connect transport's
//! verification and upload events, and it cancels on the process-wide
//! shutdown flag. [`start`] makes a terminal for one command. The returned
//! [`Guard`] writes the last progress line when it drops. [`Terminal::detached`]
//! makes a terminal that shows no progress. It still prints warnings. Callers
//! that do not show progress, such as the integration tests, use it.
//!
//! ## Interactivity gating
//!
//! Mirrors `term::use_color_stderr`'s tty auto-detection: progress is
//! shown only when stderr is a tty, unless overridden by an explicit
//! `--quiet` flag (forces off) or the `KIT_PROGRESS` env var
//! (`always`/`never`/`auto`, mirroring `NO_COLOR`/`CLICOLOR_FORCE`'s
//! override convention) — `always` is how the CLI integration tests
//! observe progress lines over a piped (non-tty) stderr. Verification waiting
//! is an exception: a piped, non-quiet push gets one start and one completion
//! line because the wait can last for minutes.

use kit_core::hash::{Hash, to_hex};
use kit_sync::{Observer, SyncEvent};
use kit_transport_connect::{PendingEvent, UploadEvent};
use std::io::{IsTerminal, Write};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// One real, already-happened unit of transfer work. Never a projection
/// or estimate.
#[derive(Debug, Clone, Copy)]
enum Event {
    /// `count` objects were appended to the outgoing pack(s) (push side,
    /// `build_and_upload_packs`'s `plan.raw` / `plan.deltas` loops).
    ObjectsPacked(usize),
    /// A finished pack (`bytes` long) was handed to
    /// `Transport::upload_pack` — that pack's upload is complete. Fires
    /// once per pack; a push whose plan exceeds a single pack's payload
    /// cap fires this more than once, and `bytes` accumulates across
    /// calls rather than reporting only the last pack.
    PackUploaded(u64),
    /// `count` objects were unpacked from one downloaded pack (pull/fetch
    /// side, `unpack_downloaded_packs`) — real counts from the pack's own
    /// [`kit_core::pack::UnpackReport`].
    ObjectsUnpacked(usize),
    /// A split push is starting advance `index` of `total`. The
    /// counters restart for it and its label carries the step.
    Step { index: usize, total: usize },
}

/// Objects between throttled stderr re-writes. The final event
/// ([`Event::PackUploaded`], and [`Guard`]'s `Drop`) always emits
/// regardless of this threshold, so the last line reflects the true
/// final count even when it doesn't land on an interval boundary.
const REPORT_INTERVAL: usize = 8;

struct Reporter {
    label: &'static str,
    total: Option<usize>,
    done: usize,
    bytes: u64,
    last_emit_done: usize,
    emitted: bool,
    step: Option<(usize, usize)>,
}

impl Reporter {
    fn new(label: &'static str, total: Option<usize>) -> Self {
        Self {
            label,
            total,
            done: 0,
            bytes: 0,
            last_emit_done: 0,
            emitted: false,
            step: None,
        }
    }

    fn record(&mut self, event: Event) {
        match event {
            Event::ObjectsPacked(n) | Event::ObjectsUnpacked(n) => {
                self.done += n;
                if self.done.saturating_sub(self.last_emit_done) >= REPORT_INTERVAL {
                    self.emit();
                }
            }
            Event::PackUploaded(bytes) => {
                // Accumulate, not overwrite: a multi-pack push
                // fires this once per pack, and the reported total must
                // cover every pack uploaded so far, not just the last one.
                self.bytes = self.bytes.saturating_add(bytes);
                self.emit();
            }
            Event::Step { index, total } => {
                self.finish();
                self.done = 0;
                self.bytes = 0;
                self.last_emit_done = 0;
                self.emitted = false;
                self.step = Some((index, total));
            }
        }
    }

    fn label(&self) -> String {
        match self.step {
            Some((index, total)) => format!("{} (step {index}/{total})", self.label),
            None => self.label.to_owned(),
        }
    }

    fn emit(&mut self) {
        self.last_emit_done = self.done;
        self.emitted = true;
        let label = self.label();
        let mut stderr = std::io::stderr().lock();
        let _ = match (self.total, self.bytes) {
            (Some(total), 0) => write!(stderr, "\r{label}: {}/{total} objects", self.done),
            (Some(total), bytes) => {
                write!(
                    stderr,
                    "\r{label}: {}/{total} objects, {bytes} bytes",
                    self.done
                )
            }
            (None, 0) => write!(stderr, "\r{label}: {} objects", self.done),
            (None, bytes) => write!(stderr, "\r{label}: {} objects, {bytes} bytes", self.done),
        };
        let _ = stderr.flush();
    }

    /// Force a final emit (bypassing the throttle) and move past the
    /// self-overwriting `\r` line so later output isn't clobbered by it.
    /// A no-op when nothing was ever reported (e.g. a no-op push).
    fn finish(&mut self) {
        if self.done == 0 && self.bytes == 0 {
            return;
        }
        self.emit();
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, ", done.");
    }
}

struct UploadReporter {
    quiet: bool,
    interactive: bool,
    active: bool,
}

impl UploadReporter {
    fn render(&mut self, event: UploadEvent) -> Option<String> {
        if self.quiet {
            return None;
        }
        match event {
            UploadEvent::PartsPlanned {
                parts,
                resumed,
                saved_bytes,
                bytes,
            } => {
                self.active = true;
                if self.interactive {
                    Some(format!(
                        "\rUploading pack: part {resumed}/{parts} ({}/{} MiB), {resumed} resumed\x1b[K",
                        saved_bytes / (1024 * 1024),
                        bytes / (1024 * 1024)
                    ))
                } else {
                    Some(format!(
                        "Uploading pack: {parts} parts, {resumed} resumed.\n"
                    ))
                }
            }
            UploadEvent::PartSent {
                index,
                parts,
                saved_bytes,
                bytes,
                resumed,
            } if self.interactive => Some(format!(
                "\rUploading pack: part {}/{parts} ({}/{} MiB), {resumed} resumed\x1b[K",
                index + 1,
                saved_bytes / (1024 * 1024),
                bytes / (1024 * 1024)
            )),
            UploadEvent::Finished if self.active => {
                self.active = false;
                if self.interactive {
                    Some("\rUploading pack: done.\x1b[K\n".to_owned())
                } else {
                    Some("Upload complete.\n".to_owned())
                }
            }
            _ => None,
        }
    }
}

struct PendingReporter {
    quiet: bool,
    interactive: bool,
    active: bool,
}

impl PendingReporter {
    fn new(quiet: bool, mode: Option<&str>, is_tty: bool) -> Self {
        Self {
            quiet: quiet || mode == Some("never"),
            interactive: mode == Some("always") || is_tty,
            active: false,
        }
    }

    fn render(&mut self, event: PendingEvent) -> Option<String> {
        if self.quiet {
            return None;
        }
        match event {
            PendingEvent::Waiting { elapsed, .. } if self.interactive => {
                self.active = true;
                Some(format!(
                    "\rWaiting for server verification: {}s\x1b[K",
                    elapsed.as_secs()
                ))
            }
            PendingEvent::Waiting { .. } if !self.active => {
                self.active = true;
                Some("Waiting for server verification...\n".to_owned())
            }
            PendingEvent::Finished { elapsed, succeeded } if self.active => {
                self.active = false;
                if self.interactive {
                    let status = if succeeded { "done" } else { "stopped" };
                    Some(format!(
                        "\rWaiting for server verification: {}s, {status}.\x1b[K\n",
                        elapsed.as_secs()
                    ))
                } else if succeeded {
                    Some("Server verification complete.\n".to_owned())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// The line a piped, non-quiet run gets when one advance of a split push has
/// landed.
fn step_line(index: usize, total: usize, head: &Hash) -> String {
    format!(
        "pushed step {index}/{total}: branch now at {}",
        to_hex(head)
    )
}

/// The line for one landed advance, or `None` when nothing should be printed:
/// a quiet run, a single advance, or an interactive run, whose live progress
/// line already carries the step.
fn step_message(
    quiet: bool,
    interactive: bool,
    index: usize,
    total: usize,
    head: &Hash,
) -> Option<String> {
    (!quiet && !interactive && total >= 2).then(|| step_line(index, total, head))
}

/// Whether progress should be shown on stderr: not explicitly silenced
/// (`--quiet` / `-q`), and either `KIT_PROGRESS` forces a decision or
/// stderr is a tty. Mirrors `term::use_color_stderr`'s
/// `NO_COLOR`/`CLICOLOR_FORCE`-style override convention — `always` is
/// how CLI integration tests observe progress lines over a piped
/// (non-tty) stderr; `never` is an explicit opt-out distinct from
/// `--quiet` (e.g. for scripting environments that set it once instead
/// of threading `--quiet` through every call site).
#[must_use]
pub fn should_report(quiet: bool) -> bool {
    if quiet {
        return false;
    }
    match std::env::var("KIT_PROGRESS").ok().as_deref() {
        Some("always") => true,
        Some("never") => false,
        _ => std::io::stderr().is_terminal(),
    }
}

/// What a [`Terminal`] shows. `quiet` is `None` for a detached terminal.
struct State {
    quiet: Option<bool>,
    reporter: Option<Reporter>,
    pending: Option<PendingReporter>,
    upload: Option<UploadReporter>,
}

/// The CLI's observer: it prints what a command shows while it transfers
/// objects. See the module documentation.
pub struct Terminal {
    state: Mutex<State>,
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Terminal").finish_non_exhaustive()
    }
}

/// Owns the terminal of one command. Dropping it writes the final progress
/// line, if anything was reported, and stops all progress output, so a
/// command holds it for the length of its transfer and lets scope exit
/// (including an early `return` on error) clean up.
#[derive(Debug)]
#[must_use = "dropping this immediately ends progress reporting"]
pub struct Guard {
    terminal: Arc<Terminal>,
}

impl Guard {
    /// The terminal to hand to the code that opens the remote and transfers.
    #[must_use]
    pub fn terminal(&self) -> &Arc<Terminal> {
        &self.terminal
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.terminal.finish();
    }
}

/// Make the terminal for one command. `enabled = false` shows no transfer
/// progress — used when stderr isn't interactive or `--quiet` was passed
/// (see [`should_report`]).
///
/// `total`, when known ahead of time, renders as `done/total`; `None` (the
/// side where the object count isn't known until each pack is downloaded)
/// renders as a running count only — never a fabricated total.
pub fn start(label: &'static str, total: Option<usize>, enabled: bool, quiet: bool) -> Guard {
    let progress_mode = std::env::var("KIT_PROGRESS").ok();
    let terminal = Terminal {
        state: Mutex::new(State {
            quiet: Some(quiet || progress_mode.as_deref() == Some("never")),
            reporter: enabled.then(|| Reporter::new(label, total)),
            pending: Some(PendingReporter::new(
                quiet,
                progress_mode.as_deref(),
                std::io::stderr().is_terminal(),
            )),
            upload: Some(UploadReporter {
                quiet: quiet || progress_mode.as_deref() == Some("never"),
                interactive: progress_mode.as_deref() == Some("always")
                    || std::io::stderr().is_terminal(),
                active: false,
            }),
        }),
    };
    Guard {
        terminal: Arc::new(terminal),
    }
}

/// Write `line` to stderr and flush it. A write failure is not worth
/// failing a transfer for.
fn write_stderr(line: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(line.as_bytes());
    let _ = stderr.flush();
}

impl Terminal {
    /// A terminal that shows no progress and prints only warnings. Library
    /// callers and tests that do not show progress use it.
    #[must_use]
    pub fn detached() -> Self {
        Self {
            state: Mutex::new(State {
                quiet: None,
                reporter: None,
                pending: None,
                upload: None,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // A panic while printing leaves the state usable: it only holds
        // counters.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stop all progress output, and write the final progress line when
    /// anything was reported.
    fn finish(&self) {
        let reporter = {
            let mut state = self.state();
            state.quiet = None;
            state.pending = None;
            state.upload = None;
            state.reporter.take()
        };
        if let Some(mut reporter) = reporter {
            reporter.finish();
        }
    }

    /// Report one real unit of already-completed transfer work. Does
    /// nothing when this terminal shows no progress.
    fn report(&self, event: Event) {
        if let Some(reporter) = self.state().reporter.as_mut() {
            reporter.record(event);
        }
    }

    /// Render a multipart upload event on stderr.
    pub fn upload_event(&self, event: UploadEvent) {
        let line = self
            .state()
            .upload
            .as_mut()
            .and_then(|reporter| reporter.render(event));
        if let Some(line) = line {
            write_stderr(&line);
        }
    }

    /// Render a verification-polling event on stderr.
    pub fn pending_event(&self, event: PendingEvent) {
        let line = self
            .state()
            .pending
            .as_mut()
            .and_then(|reporter| reporter.render(event));
        if let Some(line) = line {
            write_stderr(&line);
        }
    }

    /// End the current self-overwriting progress line before helper UX
    /// appears.
    pub fn suspend_for_admission(&self) {
        if self
            .state()
            .reporter
            .as_ref()
            .is_some_and(|reporter| reporter.emitted)
        {
            write_stderr("\n");
        }
    }

    /// Report that advance `index` of `total` of a split push has landed.
    /// A detached terminal prints nothing.
    fn step_committed(&self, index: usize, total: usize, head: &Hash) {
        let line = {
            let state = self.state();
            let Some(quiet) = state.quiet else {
                return;
            };
            step_message(quiet, state.reporter.is_some(), index, total, head)
        };
        if let Some(line) = line {
            write_stderr(&format!("{line}\n"));
        }
    }
}

/// Warn that a live `kit serve` process holds the repository at
/// `worktree_root`.
fn warn_served(worktree_root: &std::path::Path) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "warning: {} is currently being served by `kit serve`; concurrent worktree \
         mutation and `gc` are not coordinated with it (SPEC-CONCURRENCY §3.1)",
        worktree_root.display()
    );
}

/// Prints the lock helpers' events as warnings on stderr.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServedWarning;

impl Observer<libkit::lock::Event> for ServedWarning {
    fn event(&self, event: &libkit::lock::Event) {
        if let libkit::lock::Event::RepositoryServed { worktree_root } = event {
            warn_served(worktree_root);
        }
    }
}

impl Observer<SyncEvent> for Terminal {
    fn event(&self, event: &SyncEvent) {
        match event {
            SyncEvent::ObjectsPacked { count } => self.report(Event::ObjectsPacked(*count)),
            SyncEvent::PackUploaded { bytes } => self.report(Event::PackUploaded(*bytes)),
            SyncEvent::PushStep { index, total } => self.report(Event::Step {
                index: *index,
                total: *total,
            }),
            SyncEvent::PushStepCommitted { index, total, tip } => {
                self.step_committed(*index, *total, tip);
            }
            SyncEvent::ObjectsUnpacked { count } => self.report(Event::ObjectsUnpacked(*count)),
            SyncEvent::BranchSkippedStale { branch } if should_report(false) => {
                eprintln!(
                    "fetch: skipping branch `{branch}`: listed by an eventual ListRefs but \
                     no longer present (deleted since the listing)"
                );
            }
            SyncEvent::AppliedPacksUnreadable { remote, error } => {
                eprintln!(
                    "warning: could not read applied-packs record for remote '{remote}' ({error}); continuing without redownload-avoidance for this fetch"
                );
            }
            SyncEvent::AppliedPacksStale {
                remote,
                branch,
                cause,
            } => {
                eprintln!(
                    "note: applied-packs record for remote '{remote}' branch '{branch}' looks stale ({cause}); clearing it and re-fetching the full pack chain"
                );
            }
            SyncEvent::AppliedPacksPersistFailed { remote, error } => {
                eprintln!(
                    "warning: could not persist applied-packs record for remote '{remote}' ({error}); it will be rebuilt on the next fetch"
                );
            }
            SyncEvent::RepositoryServed { worktree_root } => warn_served(worktree_root),
            _ => {}
        }
    }

    fn cancelled(&self) -> bool {
        crate::signal::is_shutdown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A detached terminal shows nothing: its events change no state and
    /// it never touches stderr. This is the path every push/pull/fetch
    /// integration test takes.
    #[test]
    fn detached_terminal_ignores_progress_events() {
        let terminal = Terminal::detached();
        terminal.event(&SyncEvent::ObjectsPacked { count: 1 });
        terminal.event(&SyncEvent::PackUploaded { bytes: 128 });
        terminal.event(&SyncEvent::ObjectsUnpacked { count: 3 });
        terminal.event(&SyncEvent::PushStepCommitted {
            index: 2,
            total: 5,
            tip: [0xab; 32],
        });
        assert!(terminal.state().reporter.is_none());
        assert!(!Observer::<SyncEvent>::cancelled(&Terminal::detached()));
    }

    /// A multi-pack push fires `PackUploaded` once per
    /// pack. The reported byte total must accumulate across those
    /// calls, not report only the last pack (the bug this test pins).
    #[test]
    fn pack_uploaded_accumulates_across_multiple_packs() {
        let mut rep = Reporter::new("Writing objects", None);
        rep.record(Event::PackUploaded(100));
        assert_eq!(rep.bytes, 100);
        rep.record(Event::PackUploaded(50));
        assert_eq!(rep.bytes, 150, "second pack's bytes must add, not replace");
        rep.record(Event::PackUploaded(25));
        assert_eq!(rep.bytes, 175);
    }

    /// A disabled start installs no reporter, so events inside its scope
    /// change nothing.
    #[test]
    fn disabled_guard_installs_no_reporter() {
        let guard = start("Writing objects", Some(4), false, true);
        guard
            .terminal()
            .event(&SyncEvent::ObjectsPacked { count: 4 });
        assert!(guard.terminal().state().reporter.is_none());
    }

    /// An enabled start counts the events it receives, in order, and a
    /// finished terminal stops counting.
    #[test]
    fn enabled_guard_counts_events_until_it_finishes() {
        let guard = start("Writing objects", Some(40), true, true);
        let terminal = guard.terminal().clone();
        terminal.event(&SyncEvent::ObjectsPacked { count: 2 });
        terminal.event(&SyncEvent::PackUploaded { bytes: 10 });
        {
            let state = terminal.state();
            let reporter = state.reporter.as_ref().unwrap();
            assert_eq!((reporter.done, reporter.bytes), (2, 10));
        }
        drop(guard);
        assert!(terminal.state().reporter.is_none());
        terminal.event(&SyncEvent::ObjectsPacked { count: 9 });
        assert!(terminal.state().reporter.is_none());
    }

    #[test]
    fn pending_stderr_lines_for_piped_forced_and_quiet_modes() {
        let wait = PendingEvent::Waiting {
            elapsed: std::time::Duration::from_secs(42),
            next: std::time::Duration::from_secs(1),
        };
        let done = PendingEvent::Finished {
            elapsed: std::time::Duration::from_secs(43),
            succeeded: true,
        };
        let mut piped = PendingReporter::new(false, None, false);
        assert_eq!(
            piped.render(wait).as_deref(),
            Some("Waiting for server verification...\n")
        );
        assert_eq!(piped.render(wait), None);
        assert_eq!(
            piped.render(done).as_deref(),
            Some("Server verification complete.\n")
        );

        let mut forced = PendingReporter::new(false, Some("always"), false);
        assert_eq!(
            forced.render(wait).as_deref(),
            Some("\rWaiting for server verification: 42s\x1b[K")
        );
        assert_eq!(
            forced.render(done).as_deref(),
            Some("\rWaiting for server verification: 43s, done.\x1b[K\n")
        );

        let mut quiet = PendingReporter::new(true, Some("always"), false);
        assert_eq!(quiet.render(wait), None);
        assert_eq!(quiet.render(done), None);

        let mut never = PendingReporter::new(false, Some("never"), true);
        assert_eq!(never.render(wait), None);
        assert_eq!(never.render(done), None);
    }

    #[test]
    fn upload_progress_shows_resumed_bytes_on_tty_and_two_lines_when_piped() {
        let start = UploadEvent::PartsPlanned {
            parts: 12,
            resumed: 4,
            saved_bytes: 32 << 20,
            bytes: 96 << 20,
        };
        let sent = UploadEvent::PartSent {
            index: 4,
            parts: 12,
            saved_bytes: 40 << 20,
            bytes: 96 << 20,
            resumed: 4,
        };
        let mut tty = UploadReporter {
            quiet: false,
            interactive: true,
            active: false,
        };
        assert!(tty.render(start).unwrap().contains("part 4/12 (32/96 MiB)"));
        assert!(
            tty.render(sent)
                .unwrap()
                .contains("part 5/12 (40/96 MiB), 4 resumed")
        );
        assert!(tty.render(UploadEvent::Finished).unwrap().contains("done."));

        let mut piped = UploadReporter {
            quiet: false,
            interactive: false,
            active: false,
        };
        assert_eq!(
            piped.render(start).as_deref(),
            Some("Uploading pack: 12 parts, 4 resumed.\n")
        );
        assert_eq!(piped.render(sent), None);
        assert_eq!(
            piped.render(UploadEvent::Finished).as_deref(),
            Some("Upload complete.\n")
        );
    }

    /// `should_report` precedence: `--quiet` wins outright, then
    /// `KIT_PROGRESS`, then tty-ness. Exercised via the pure
    /// tty-independent branches only (quiet, and the env var forcing a
    /// decision) — this process's stderr tty-ness varies by how tests
    /// are invoked, so the `_ =>` fallthrough isn't asserted here.
    #[test]
    fn should_report_quiet_always_wins() {
        assert!(!should_report(true));
    }

    /// A split push: the live progress line names the step, a
    /// piped run gets one line per landed advance, a quiet run and a single
    /// advance get none.
    #[test]
    fn split_push_output_in_tty_piped_and_quiet_modes() {
        let mut reporter = Reporter::new("Writing objects", None);
        assert_eq!(reporter.label(), "Writing objects");
        reporter.record(Event::Step { index: 2, total: 5 });
        assert_eq!(reporter.label(), "Writing objects (step 2/5)");
        assert_eq!((reporter.done, reporter.bytes), (0, 0));

        let head = [0xab; 32];
        let hex = to_hex(&head);
        assert_eq!(
            step_message(false, false, 2, 5, &head),
            Some(format!("pushed step 2/5: branch now at {hex}"))
        );
        assert_eq!(step_message(false, true, 2, 5, &head), None, "tty");
        assert_eq!(step_message(true, false, 2, 5, &head), None, "quiet");
        assert_eq!(step_message(false, false, 1, 1, &head), None, "unsplit");
    }
}
