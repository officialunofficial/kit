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
    let _ = writeln!(
        std::io::stderr().lock(),
        "maintenance: retired {} dead local pack(s), removed {} leftover, {}.{} MiB",
        report.packs_retired,
        report.leftovers_removed,
        tenths / 10,
        tenths % 10,
    );
}

pub(super) fn json_field(top: &mut JsonObject, report: Option<&MaintenanceReport>) {
    let Some(report) = report.filter(|r| r.collection != Collection::NotDue || changed(r)) else {
        return;
    };
    let mut json = JsonObject::new();
    json.field_u64("leftovers_removed", report.leftovers_removed as u64)
        .field_u64("packs_retired", report.packs_retired as u64)
        .field_u64("bytes_reclaimed", report.bytes_reclaimed)
        .field_str("collection", report.collection.as_str())
        .field_raw("elapsed", &report.elapsed.as_millis().to_string());
    top.field_raw("maintenance", &json.finish());
}

fn changed(report: &MaintenanceReport) -> bool {
    report.leftovers_removed != 0 || report.packs_retired != 0
}
