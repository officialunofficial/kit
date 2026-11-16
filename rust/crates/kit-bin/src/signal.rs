//! Signal handling — SIGINT / SIGTERM set a graceful-shutdown flag in the
//! commands that [`defers_interrupt`] names. The transfer commands, `log`,
//! `reflog` and the grant commands poll it at natural checkpoints, so a
//! `Ctrl-C` aborts them cleanly with `exit::TEMPFAIL` (75) rather than
//! leaving a half-finished transfer. The commands that run a multi-step
//! operation (`merge`, `rebase`, `cherry-pick`, `revert`, `stash`, `bisect`,
//! `worktree`, `remote`, `git pull`) do not poll it: the first signal lets
//! them finish, so their state on disk is never cut between two writes. In
//! all of them a second signal takes the default action and ends the
//! process.
//!
//! Every other command keeps the default action, so a `Ctrl-C` stops it at
//! once. Each of its writes is a temp file renamed into place, so a stopped
//! command leaves the repository as it was after its last finished write: a
//! checkout and a reset write the files first and then their refs and the
//! index together, so a stopped one leaves the files it wrote as local
//! changes. `gc` sweeps the object temp files a stopped command leaves, the
//! next restore that writes into a directory removes the worktree temp files
//! there, and a temp file beside a ref is never read.
//!
//! While an editor runs ([`while_editor_runs`]), kit ignores SIGINT and
//! SIGQUIT, as git does: the editor gets the terminal's `Ctrl-C`, and kit
//! waits for it to exit; SIGTERM still ends kit. [`defer`] holds SIGINT and
//! SIGTERM across writes that must not be split, such as HEAD and the index
//! of a checkout.
//!
//! Only the `kit` binary handles signals: `main` calls [`enable`] before
//! [`crate::dispatch`]. A process that drives `dispatch` as a library and
//! never calls [`enable`] gets no handler from [`install`], [`defer`] or
//! [`while_editor_runs`]; SIGINT, SIGTERM and SIGQUIT keep the disposition
//! that process set.
//!
//! A command started with SIGINT ignored, as a shell starts a background job,
//! keeps ignoring it only until it installs a handler: [`install`], an editor
//! or a [`defer`] replaces the inherited disposition.
//!
//! ## SIGPIPE is intentionally not registered here
//!
//! Rust's runtime sets `SIGPIPE` to `SIG_IGN` at process start since
//! 1.65, which means `write(2)` on a closed pipe returns `EPIPE`
//! instead of terminating the process. The CLI uses
//! `let _ = writeln!(stdout, …)` everywhere, so the `EPIPE` propagates
//! as a silently-dropped `io::Error` and the program exits at its
//! next natural completion point — exactly the pipeline-friendly
//! behaviour `docs/CLI.md` advertises.
//!
//! Registering a signal-hook handler over the runtime's `SIG_IGN`
//! would replace a clean kernel-level ignore with a userspace handler
//! that does an atomic store and returns — observationally
//! equivalent but strictly worse (extra wakeups, a window where a
//! different thread might briefly observe a flipped flag we never
//! consume). The integration test in `tests/sigpipe.rs` is the
//! regression guard: it pipes `kit cat <large-blob>` through
//! `head -1` and asserts the left-hand exit code is `0`. If anyone
//! ever opts kit out of Rust's default with `#[unix_sigpipe]`, that
//! test goes red.
//!
//! ## Implementation
//!
//! `signal-hook`'s `flag` module installs the handlers via
//! `sigaction(2)` and exposes a fully safe API (atomic-bool stores
//! are async-signal-safe; the `unsafe` lives inside the crate). The
//! CLI stays under its crate-level `#![deny(unsafe_code)]`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Shared shutdown flag. Lazily initialised so tests that exercise the
/// flag without going through [`install`] still observe a coherent
/// value. The `Arc` is required because `signal_hook::flag::register`
/// takes an owned `Arc<AtomicBool>` — it does not accept a `&'static`.
static SHUTDOWN: OnceLock<Arc<AtomicBool>> = OnceLock::new();

fn shutdown_flag() -> &'static Arc<AtomicBool> {
    SHUTDOWN.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

/// Set by a first SIGINT or SIGTERM once [`install`] ran. A SIGINT, and a
/// SIGTERM, that arrives while its flag is set takes the default action.
static ARMED: OnceLock<Arc<AtomicBool>> = OnceLock::new();
/// SIGTERM's flag. [`while_editor_runs`] sets it while the editor runs, so a
/// SIGTERM then ends kit at once.
static ARMED_TERM: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// The actions that arm SIGINT's default action. [`while_editor_runs`]
/// removes them while an editor runs, and puts them back after.
#[cfg(unix)]
static ARMING: Mutex<Vec<signal_hook::SigId>> = Mutex::new(Vec::new());

/// Whether [`install`] ran.
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Whether this process handles signals: set by [`enable`].
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Let kit handle signals in this process. The `kit` binary calls it once,
/// before [`crate::dispatch`]. Without it, [`install`], [`defer`] and
/// [`while_editor_runs`] register no handler, so a process that embeds
/// `dispatch` keeps its own signal dispositions.
pub fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Whether SIGINT, SIGTERM and SIGQUIT take their default action now, in a
/// command that did not run [`install`]. [`while_editor_runs`] and [`defer`]
/// clear them.
static FATAL_INT: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static FATAL_TERM: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static FATAL_QUIT: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Set by a SIGINT or SIGTERM that a [`defer`] held.
static PENDING_INT: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static PENDING_TERM: OnceLock<Arc<AtomicBool>> = OnceLock::new();

fn flag(cell: &'static OnceLock<Arc<AtomicBool>>, initial: bool) -> Arc<AtomicBool> {
    Arc::clone(cell.get_or_init(|| Arc::new(AtomicBool::new(initial))))
}

/// Install SIGINT/SIGTERM handlers that flip the shared shutdown flag, for a
/// command that [`defers_interrupt`]. A signal that arrives once a first one
/// was taken runs the signal's default action, which ends the process, so a
/// second `Ctrl-C` always stops it.
///
/// It is a no-op unless [`enable`] ran, and on non-Unix targets (Windows
/// signal semantics differ; the CLI does not currently ship on Windows).
pub fn install() {
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};
        use signal_hook::flag::{register, register_conditional_default};

        if !enabled() {
            return;
        }

        INSTALLED.store(true, Ordering::Relaxed);
        // Errors here are effectively unreachable (they only fail if
        // the OS refuses to install a handler, e.g. for SIGKILL).
        // Silently fall back to the default disposition in that case.
        // The default action goes first: it must see the flag as it was
        // before this signal set it.
        for (signal, armed) in [(SIGINT, &ARMED), (SIGTERM, &ARMED_TERM)] {
            let _ = register_conditional_default(signal, flag(armed, false));
            let _ = register(signal, Arc::clone(shutdown_flag()));
        }
        let _ = register(SIGTERM, flag(&ARMED, false));
        let _ = register(SIGTERM, flag(&ARMED_TERM, false));
        arm_sigint();
    }
}

#[cfg(unix)]
fn arm_sigint() {
    for armed in [&ARMED, &ARMED_TERM] {
        if let Ok(id) = signal_hook::flag::register(signal_hook::consts::SIGINT, flag(armed, false))
            && let Ok(mut arming) = ARMING.lock()
        {
            arming.push(id);
        }
    }
}

/// Whether `command` takes [`install`]'s handlers: it polls [`is_shutdown`],
/// or it runs a multi-step operation that a first signal must not cut. Every
/// other command keeps the default action of SIGINT and SIGTERM.
#[must_use]
pub fn defers_interrupt(command: &str, args: &[String]) -> bool {
    // `git pull` moves a branch, then writes the worktree and the index.
    if command == "git" {
        return args.first().is_some_and(|sub| sub == "pull");
    }
    matches!(
        command,
        "push"
            | "pull"
            | "fetch"
            | "clone"
            | "log"
            | "reflog"
            | "grant"
            | "epoch"
            | "visibility"
            | "merge"
            | "rebase"
            | "cherry-pick"
            | "revert"
            | "stash"
            | "bisect"
            | "worktree"
            | "remote"
    )
}

/// Register, once, the actions [`while_editor_runs`] and [`defer`] switch.
/// Until one of them runs, a command that did not run [`install`] keeps the
/// default actions without any handler.
#[cfg(unix)]
fn switchable() {
    use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM};
    use signal_hook::flag::{register, register_conditional_default};

    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if !INSTALLED.load(Ordering::Relaxed) {
            for (signal, fatal, pending) in [
                (SIGINT, &FATAL_INT, &PENDING_INT),
                (SIGTERM, &FATAL_TERM, &PENDING_TERM),
            ] {
                // The pending flag goes first: a signal that `defer` reads
                // as not pending has then found its action fatal.
                let _ = register(signal, flag(pending, false));
                let _ = register_conditional_default(signal, flag(fatal, true));
            }
        }
        let _ = register_conditional_default(SIGQUIT, flag(&FATAL_QUIT, true));
    });
}

/// Run `run`, which starts an editor and waits for it, with SIGINT and
/// SIGQUIT ignored by kit, as git does. The terminal sends `Ctrl-C` to the
/// editor too, and an editor such as vim uses it; kit must not die and leave
/// the editor without its terminal. The editor itself keeps the default
/// actions: a signal kit catches is reset when the editor starts.
///
/// Without [`enable`], `run` just runs.
pub fn while_editor_runs<T>(run: impl FnOnce() -> T) -> T {
    #[cfg(unix)]
    {
        if !enabled() {
            return run();
        }
        switchable();
        let installed = INSTALLED.load(Ordering::Relaxed);
        flag(&FATAL_INT, true).store(false, Ordering::SeqCst);
        flag(&FATAL_QUIT, true).store(false, Ordering::SeqCst);
        let armed = flag(&ARMED, false).load(Ordering::SeqCst);
        let armed_term = flag(&ARMED_TERM, false).load(Ordering::SeqCst);
        if installed {
            if let Ok(mut arming) = ARMING.lock() {
                for id in arming.drain(..) {
                    signal_hook::low_level::unregister(id);
                }
            }
            // SIGINT is ignored; SIGTERM ends kit at once, as it does git.
            flag(&ARMED, false).store(false, Ordering::SeqCst);
            flag(&ARMED_TERM, false).store(true, Ordering::SeqCst);
        }
        let shutdown = shutdown_flag().load(Ordering::SeqCst);
        let result = run();
        // A Ctrl-C meant for the editor does not count; one taken before it
        // still does.
        if installed {
            shutdown_flag().store(shutdown, Ordering::SeqCst);
            flag(&ARMED, false).store(armed, Ordering::SeqCst);
            flag(&ARMED_TERM, false).store(armed_term, Ordering::SeqCst);
            arm_sigint();
        }
        flag(&PENDING_INT, false).store(false, Ordering::SeqCst);
        flag(&FATAL_QUIT, true).store(true, Ordering::SeqCst);
        flag(&FATAL_INT, true).store(true, Ordering::SeqCst);
        result
    }
    #[cfg(not(unix))]
    run()
}

/// Run `run`, two writes that must not be split, with SIGINT and SIGTERM
/// held: one that arrives meanwhile takes its default action once `run`
/// returns. A command that ran [`install`] defers its first signal anyway, so
/// there `run` just runs, as it does without [`enable`].
pub fn defer<T>(run: impl FnOnce() -> T) -> T {
    #[cfg(unix)]
    {
        if !enabled() || INSTALLED.load(Ordering::Relaxed) {
            return run();
        }
        switchable();
        let (int, term) = (flag(&PENDING_INT, false), flag(&PENDING_TERM, false));
        int.store(false, Ordering::SeqCst);
        term.store(false, Ordering::SeqCst);
        flag(&FATAL_INT, true).store(false, Ordering::SeqCst);
        flag(&FATAL_TERM, true).store(false, Ordering::SeqCst);
        let result = run();
        flag(&FATAL_INT, true).store(true, Ordering::SeqCst);
        flag(&FATAL_TERM, true).store(true, Ordering::SeqCst);
        for (pending, signal) in [
            (int, signal_hook::consts::SIGINT),
            (term, signal_hook::consts::SIGTERM),
        ] {
            if pending.load(Ordering::SeqCst) {
                // The default action now applies, and ends the process.
                let _ = signal_hook::low_level::raise(signal);
            }
        }
        result
    }
    #[cfg(not(unix))]
    run()
}

/// Returns `true` once a shutdown was requested via signal. Long-
/// running poll loops should call this at natural checkpoints and
/// return `exit::TEMPFAIL` when it flips.
#[must_use]
pub fn is_shutdown() -> bool {
    SHUTDOWN.get().is_some_and(|f| f.load(Ordering::Relaxed))
}

/// Test hook — flips the shutdown flag so unit tests can verify that
/// long-running callers do honour it once it flips.
#[doc(hidden)]
pub fn set_interrupted_for_tests(v: bool) {
    shutdown_flag().store(v, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_round_trips() {
        set_interrupted_for_tests(true);
        assert!(is_shutdown());
        set_interrupted_for_tests(false);
        assert!(!is_shutdown());
    }

    #[test]
    fn the_commands_that_defer_an_interrupt() {
        let args = |list: &[&str]| list.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
        assert!(defers_interrupt("push", &[]));
        assert!(defers_interrupt("rebase", &args(&["-i", "HEAD~1"])));
        assert!(defers_interrupt("git", &args(&["pull"])));
        assert!(!defers_interrupt("git", &args(&["import"])));
        assert!(!defers_interrupt("git", &[]));
        assert!(!defers_interrupt("add", &[]));
        assert!(!defers_interrupt("checkout", &[]));
    }

    /// `install()` must not pre-flip the flag — long-running callers
    /// poll `is_shutdown()` and would otherwise abort immediately.
    #[test]
    fn install_then_is_shutdown_returns_false() {
        set_interrupted_for_tests(false);
        enable();
        install();
        assert!(!is_shutdown());
    }

    /// Double-install must not panic. Tests share a process, so any
    /// other test that calls `install()` first must leave this one
    /// in a working state.
    #[test]
    fn install_is_idempotent() {
        // Double-install must not panic (asserted by simply reaching
        // this point), AND the shared flag must still behave correctly
        // afterwards — a naive re-registration bug could double-flip,
        // wedge, or otherwise desync the flag from `is_shutdown()`.
        enable();
        install();
        install();
        set_interrupted_for_tests(false);
        assert!(
            !is_shutdown(),
            "flag must read false after double-install + reset"
        );
        set_interrupted_for_tests(true);
        assert!(
            is_shutdown(),
            "flag must still flip to true after double-install"
        );
        set_interrupted_for_tests(false);
        assert!(!is_shutdown(), "flag must reset back to false");
    }
}
