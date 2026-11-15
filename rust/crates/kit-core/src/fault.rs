//! Injected write failures, for tests of how a full disk ends a transfer.
//!
//! Built with the `fault-injection` feature,
//! which only test builds turn on. A failure applies to every thread of the
//! process until its guard drops, so a test that injects one runs alone.

use std::io;
use std::sync::atomic::{AtomicU8, Ordering};

/// Where a write fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Site {
    /// A positioned write to a spool file: every write a fetch makes to its
    /// spool.
    Spool = 1,
    /// A write to an object file of the store.
    Store = 2,
}

static FAILING: AtomicU8 = AtomicU8::new(0);

/// Every write at `site` fails as a full disk until the guard drops.
#[must_use = "the failure ends when the guard drops"]
pub fn fail_writes(site: Site) -> Guard {
    FAILING.fetch_or(site as u8, Ordering::SeqCst);
    Guard(site)
}

/// Ends an injected failure when dropped.
#[derive(Debug)]
pub struct Guard(Site);

impl Drop for Guard {
    fn drop(&mut self) {
        FAILING.fetch_and(!(self.0 as u8), Ordering::SeqCst);
    }
}

/// The injected failure of a write at `site`, if any.
pub(crate) fn check(site: Site) -> io::Result<()> {
    if FAILING.load(Ordering::SeqCst) & site as u8 == 0 {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::StorageFull))
    }
}
