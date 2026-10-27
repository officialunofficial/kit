//! The terminal side of the conflict workflow.
//!
//! The logic lives in [`libkit::conflict`]. This module prints the note
//! for each path that the library writes.

use std::io::Write;

use libkit::Observer;
use libkit::conflict::{ConflictClass, Event};

/// Prints one note on stderr for each conflicting path.
#[derive(Debug)]
pub struct Notes;

impl Observer<Event> for Notes {
    fn event(&self, event: &Event) {
        note(event);
    }
}

/// Print the note for one event.
pub fn note(event: &Event) {
    let Event::Materialized { path, class } = event else {
        return;
    };
    let how = match class {
        ConflictClass::TextMarkers => "text conflict — edit markers",
        ConflictClass::Binary => "binary conflict — resolve manually, then `kit add`",
        ConflictClass::DeleteModify => "delete/modify — keep with `kit add` or drop with `kit rm`",
        ConflictClass::Special => "mode/symlink conflict — resolve manually, then `kit add`",
        _ => return,
    };
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "  {path} ({how})");
}
