//! CLI configuration of the packmap rollover policy.
use libkit::transfer::DEFAULT_REBASELINE_DEPTH;

/// Resolve the re-baseline threshold: the `KIT_PACK_REBASELINE_DEPTH`
/// environment variable if present and parsable, else
/// [`DEFAULT_REBASELINE_DEPTH`]. A value of `0` turns the reset off. The text
/// of a warning comes back when the variable is set but not valid.
pub(crate) fn configured_depth() -> (usize, Option<String>) {
    match std::env::var("KIT_PACK_REBASELINE_DEPTH") {
        Err(_) => (DEFAULT_REBASELINE_DEPTH, None),
        Ok(s) => match s.parse::<usize>() {
            Ok(depth) => (depth, None),
            Err(_) => (
                DEFAULT_REBASELINE_DEPTH,
                Some(format!(
                    "warning: KIT_PACK_REBASELINE_DEPTH='{s}' is not a valid non-negative integer; using the default {DEFAULT_REBASELINE_DEPTH} (set it to 0 to disable re-baselining)"
                )),
            ),
        },
    }
}
