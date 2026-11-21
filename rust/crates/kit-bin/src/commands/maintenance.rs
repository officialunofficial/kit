use std::io::Write;

use kit_sync::{Collection, MaintenanceReport};

use crate::format::JsonObject;

pub(super) fn print(report: Option<&MaintenanceReport>, quiet: bool) {
    const MIB: u64 = 1024 * 1024;
    let Some(report) = report.filter(|report| !quiet && changed(report)) else {
        return;
    };
    let bytes = report.bytes_reclaimed;
    let tenths = bytes / MIB * 10 + (bytes % MIB * 10 + MIB / 2) / MIB;
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "maintenance: retired {} dead local pack(s), removed {} leftover, {}.{} MiB",
        report.packs_retired,
        report.leftovers_removed,
        tenths / 10,
        tenths % 10,
    );
    if copied(report) {
        let _ = writeln!(
            stderr,
            "maintenance: rewrote {}, merged {} and retired {} covered local pack(s), copying {} byte(s)",
            report.packs_rewritten,
            report.packs_merged,
            report.packs_retired_covered,
            report.bytes_copied,
        );
    }
}

/// Run the automatic step after a command that wrote objects, when it is due.
/// The step only tries locks and runs within its own budget; it never changes
/// the command's result, and its only output is the maintenance line.
pub(super) fn after_write(
    layout: &kit_core::layout::RepoLayout,
    store: &kit_core::store::ObjectStore,
    cfg: &libkit::config::Config,
    quiet: bool,
) {
    if !cfg.gc_auto_enabled() {
        return;
    }
    let report = kit_core::ops::gc::maintain_packs(layout, store, &crate::signal::is_shutdown);
    print(Some(&report), quiet);
}

pub(super) fn json_field(top: &mut JsonObject, report: Option<&MaintenanceReport>) {
    let Some(report) = report.filter(|r| r.collection != Collection::NotDue || changed(r)) else {
        return;
    };
    let mut json = JsonObject::new();
    json.field_u64("leftovers_removed", report.leftovers_removed as u64)
        .field_u64("packs_retired", report.packs_retired as u64)
        .field_u64("packs_rewritten", report.packs_rewritten as u64)
        .field_u64("packs_merged", report.packs_merged as u64)
        .field_u64("packs_retired_covered", report.packs_retired_covered as u64)
        .field_u64("bytes_copied", report.bytes_copied)
        .field_u64("bytes_reclaimed", report.bytes_reclaimed)
        .field_str("collection", report.collection.as_str())
        .field_raw("elapsed", &report.elapsed.as_millis().to_string());
    top.field_raw("maintenance", &json.finish());
}

fn copied(report: &MaintenanceReport) -> bool {
    report.packs_rewritten != 0
        || report.packs_merged != 0
        || report.packs_retired_covered != 0
        || report.bytes_copied != 0
}

fn changed(report: &MaintenanceReport) -> bool {
    report.leftovers_removed != 0 || report.packs_retired != 0 || copied(report)
}
