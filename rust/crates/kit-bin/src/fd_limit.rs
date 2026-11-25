//! Raise the soft open-file limit at startup.
//!
//! macOS starts a process with a soft limit of 256 while the hard limit is
//! far higher. The pack handle cache and the sync worker cap size themselves
//! from the soft limit, so at 256 a store with hundreds of packs reopens
//! packs over and over. The `kit` binary raises the soft limit once, before
//! any of that is read. A library caller of `dispatch` keeps its own limit.

/// The soft limit the binary asks for. It is also under the macOS per-process
/// ceiling (`OPEN_MAX`, 10240), so the call does not fail there, and it keeps
/// the descriptor table of child processes small.
#[cfg(unix)]
const TARGET_SOFT_LIMIT: u64 = 8192;

/// The soft limit to request given the current soft and hard limits, or
/// `None` when the soft limit is already at the target or cannot go higher.
/// `None` for a limit means no limit.
#[cfg(unix)]
fn raised_soft_limit(soft: Option<u64>, hard: Option<u64>) -> Option<u64> {
    let wanted = hard.map_or(TARGET_SOFT_LIMIT, |hard| hard.min(TARGET_SOFT_LIMIT));
    soft.is_some_and(|soft| wanted > soft).then_some(wanted)
}

/// Raise the soft `RLIMIT_NOFILE` toward the hard limit, at most
/// 8,192. A failure leaves the limit as it was and is ignored:
/// the cache then sizes itself from the limit it has.
#[cfg(unix)]
pub fn raise_open_file_limit() {
    use rustix::process::{Resource, getrlimit, setrlimit};

    let limit = getrlimit(Resource::Nofile);
    if let Some(wanted) = raised_soft_limit(limit.current, limit.maximum) {
        let _ = setrlimit(
            Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(wanted),
                maximum: limit.maximum,
            },
        );
    }
}

/// There is no descriptor limit to raise off Unix.
#[cfg(not(unix))]
pub fn raise_open_file_limit() {}

#[cfg(all(test, unix))]
mod tests {
    use rustix::process::{Resource, getrlimit};

    use super::*;

    #[test]
    fn raises_to_the_target_when_the_hard_limit_allows() {
        assert_eq!(raised_soft_limit(Some(256), None), Some(TARGET_SOFT_LIMIT));
        assert_eq!(
            raised_soft_limit(Some(256), Some(1 << 20)),
            Some(TARGET_SOFT_LIMIT)
        );
    }

    #[test]
    fn stops_at_the_hard_limit() {
        assert_eq!(raised_soft_limit(Some(256), Some(4096)), Some(4096));
    }

    #[test]
    fn never_lowers_the_limit() {
        assert_eq!(raised_soft_limit(Some(8192), None), None);
        assert_eq!(raised_soft_limit(Some(65_536), None), None);
        assert_eq!(raised_soft_limit(Some(256), Some(256)), None);
        assert_eq!(raised_soft_limit(Some(1024), Some(512)), None);
        assert_eq!(raised_soft_limit(None, None), None);
    }

    /// Set when the test binary runs itself under a low soft limit.
    const CHILD_ENV: &str = "KIT_FD_LIMIT_TEST_CHILD";

    /// The body the parent test runs in a child process, so the process-wide
    /// limit of the test binary is never lowered while other tests run. It
    /// does nothing in a normal run.
    #[test]
    fn child_raises_the_limit() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let before = getrlimit(Resource::Nofile);
        let Some(soft) = before.current else {
            return;
        };
        raise_open_file_limit();
        let after = getrlimit(Resource::Nofile);
        let wanted = before
            .maximum
            .map_or(TARGET_SOFT_LIMIT, |hard| hard.min(TARGET_SOFT_LIMIT));
        assert_eq!(after.current, Some(soft.max(wanted)));
        assert_eq!(after.maximum, before.maximum);
        raise_open_file_limit();
        assert_eq!(getrlimit(Resource::Nofile), after);
    }

    #[test]
    fn raises_a_low_soft_limit_in_a_child_process() {
        if std::env::var_os(CHILD_ENV).is_some() {
            return;
        }
        // `ulimit -Sn` lowers only this child's soft limit, which is always
        // allowed. If the shell cannot set it, the limit stays where it was
        // and the child checks that instead.
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg("ulimit -Sn 256 2>/dev/null; exec \"$0\" --exact fd_limit::tests::child_raises_the_limit --test-threads 1")
            .arg(std::env::current_exe().expect("test binary path"))
            .env(CHILD_ENV, "1")
            .output()
            .expect("run the test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("1 passed"), "child ran no test:\n{stdout}");
    }
}
