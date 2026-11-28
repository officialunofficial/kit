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

/// The rerere settings of the repository. A config that cannot be read
/// leaves the cache off.
#[must_use]
pub fn rerere(layout: &kit_core::layout::RepoLayout) -> libkit::rerere::Settings {
    crate::config::read_or_default(layout).map_or_else(
        |_| libkit::rerere::Settings::default(),
        |cfg| libkit::rerere::Settings {
            enabled: cfg.rerere_enabled(),
            auto_update: cfg.rerere_auto_update_enabled(),
        },
    )
}

/// Print the note for one event.
pub fn note(event: &Event) {
    let line = match event {
        Event::ReusedResolution { path } => {
            format!(
                "Resolved '{}' using previous resolution.",
                super::display_path(path)
            )
        }
        Event::RecordedPreimage { path } => {
            format!("Recorded preimage for '{}'", super::display_path(path))
        }
        Event::RecordedResolution { path } => {
            format!("Recorded resolution for '{}'.", super::display_path(path))
        }
        Event::RerereWarning { message } => format!(
            "warning: {}",
            kit_core::protocol::escape_terminal_text(message, false)
        ),
        _ => String::new(),
    };
    if !line.is_empty() {
        let _ = writeln!(std::io::stderr().lock(), "{line}");
        return;
    }
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
    let _ = writeln!(stderr, "  {} ({how})", super::display_path(path));
}
