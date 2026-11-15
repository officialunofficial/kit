//! What `fetch`, `pull` and `clone` print about the remote's tags.
//!
//! A refused tag does not stop the other tags or any branch. The command
//! prints one line for it and exits 1 after everything else is published.

use std::io::Write;

use clap::Args;
use kit_sync::FetchReport;

use crate::exit;
use crate::format::{self, JsonObject};

/// `--tags` and `--no-tags`. The last one given wins.
#[derive(Debug, Args)]
pub(crate) struct TagFlags {
    /// Fetch every remote tag. This is the default.
    #[arg(long, overrides_with = "no_tags")]
    tags: bool,
    /// Fetch no tags.
    #[arg(long = "no-tags", overrides_with = "tags")]
    no_tags: bool,
}

impl TagFlags {
    /// Whether the fetch takes the remote's tags.
    pub(crate) fn fetch_tags(&self) -> bool {
        !self.no_tags
    }
}

/// Print one `[new tag]` line for each tag the fetch published.
pub(crate) fn print_new(report: &FetchReport, err: &mut impl Write) {
    for name in &report.tags_fetched {
        let _ = writeln!(err, " * [new tag]         {name} -> {name}");
    }
}

/// Print each refused tag, each skipped name and a failed listing. Returns
/// the exit status these alone give: 1 for a refusal or a failed listing,
/// and 0 for warnings only.
pub(crate) fn print_problems(report: &FetchReport, err: &mut impl Write) -> u8 {
    for warning in &report.tag_warnings {
        let _ = writeln!(
            err,
            "warning: skipped remote tag '{}': {}",
            warning.name, warning.reason
        );
    }
    for rejection in &report.tags_rejected {
        let name = &rejection.name;
        let _ = writeln!(
            err,
            " ! [rejected]        {name} -> {name} ({})",
            rejection.reason
        );
    }
    if let Some(reason) = &report.tag_listing_failed {
        let _ = writeln!(err, "error: {reason}");
    }
    if report.tags_incomplete() {
        exit::GENERAL_ERROR
    } else {
        exit::OK
    }
}

/// Add the tag fields to a `--format=json` object: `tags` (the names
/// published), `tags_rejected` (`{"name","reason"}` each), `tag_warnings`
/// (the same shape) and `tag_listing_failed` (a message or null).
pub(crate) fn json_fields(obj: &mut JsonObject, report: &FetchReport) {
    let names: Vec<String> = report
        .tags_fetched
        .iter()
        .map(|name| format!("\"{}\"", format::json_escape(name)))
        .collect();
    let pair = |name: &str, reason: &str| {
        let mut entry = JsonObject::new();
        entry.field_str("name", name).field_str("reason", reason);
        entry.finish()
    };
    let rejected: Vec<String> = report
        .tags_rejected
        .iter()
        .map(|r| pair(&r.name, &r.reason.to_string()))
        .collect();
    let warnings: Vec<String> = report
        .tag_warnings
        .iter()
        .map(|w| pair(&w.name, &w.reason))
        .collect();
    obj.field_raw("tags", &format!("[{}]", names.join(",")))
        .field_raw("tags_rejected", &format!("[{}]", rejected.join(",")))
        .field_raw("tag_warnings", &format!("[{}]", warnings.join(",")))
        .field_opt_str("tag_listing_failed", report.tag_listing_failed.as_deref());
}
