//! `diff --stat` rendering: git-compatible per-file rows, the `N files
//! changed` summary, and the +/- graph, sized to the terminal.
//!
//! The library counts the changes of each file. This module only lays them
//! out.

use std::io::Write;

use libkit::diff::{FileStat, StatChange};

/// Render `git diff --stat`-compatible output: one `<name> | <count>
/// <graph>` row per changed file, then a `N files changed, …` summary.
///
/// Layout matches git: the name column is padded to the longest display
/// name, the count column is right-aligned to the widest total, and the
/// `+`/`-` graph is scaled to the terminal width when the largest change
/// would overflow it. Width = `COLUMNS` (if a positive integer) else 80,
/// exactly as git does even when stdout is not a tty.
pub(in crate::commands) fn render_stat(
    out: &mut impl Write,
    stats: &[FileStat],
) -> Result<(), String> {
    if stats.is_empty() {
        return Ok(());
    }
    // The display name is C-style quoted (git `core.quotePath`) when needed.
    let names: Vec<String> = stats
        .iter()
        .map(|row| super::c_quote_name(&row.path))
        .collect();

    // Column metrics. `max_change` and the count-column width come from
    // text rows only (binary rows render `Bin …`, not a number).
    let name_width = names
        .iter()
        .map(|name| name.chars().count())
        .max()
        .unwrap_or(0);
    let max_change = stats
        .iter()
        .filter_map(|r| match r.change {
            StatChange::Text { added, deleted } => Some(added + deleted),
            StatChange::Binary { .. } => None,
        })
        .max()
        .unwrap_or(0);
    let number_width = decimal_width(max_change);

    // Graph width: COLUMNS (or 80) minus the fixed framing (leading space,
    // " | ", the count column, and the space before the graph) — the
    // reservation git uses, derived empirically as `name + number + 6`.
    let total_width = terminal_columns();
    let graph_width = total_width
        .saturating_sub(name_width)
        .saturating_sub(number_width)
        .saturating_sub(6)
        .max(1);
    // git scales the graph only when the largest change can't fit.
    let scaled = max_change > graph_width;

    for (r, name) in stats.iter().zip(&names) {
        match r.change {
            StatChange::Text { added, deleted } => {
                let total = added + deleted;
                let graph = stat_graph(added, deleted, graph_width, max_change, scaled);
                // git emits `| 0` with no trailing space/graph for a
                // zero-change row (empty-file add, mode-only); the graph
                // (and its leading space) appear only when there is one.
                if graph.is_empty() {
                    writeln!(out, " {name:<name_width$} | {total:>number_width$}")
                } else {
                    writeln!(out, " {name:<name_width$} | {total:>number_width$} {graph}")
                }
                .map_err(|e| format!("write: {e}"))?;
            }
            StatChange::Binary { old_len, new_len } => {
                writeln!(
                    out,
                    " {name:<name_width$} | Bin {old_len} -> {new_len} bytes"
                )
                .map_err(|e| format!("write: {e}"))?;
            }
        }
    }

    writeln!(out, "{}", stat_summary(stats)).map_err(|e| format!("write: {e}"))?;
    Ok(())
}

/// The ` N files changed[, I insertions(+)][, D deletions(-)]` summary
/// line, matching git's `print_stat_summary`. git's clause rule: show
/// insertions when `ins != 0 || del == 0`, and deletions when
/// `del != 0 || ins == 0`. So a one-sided change shows only its side
/// (`1 file changed, 1 insertion(+)`), while a zero-change diff (mode-only,
/// binary-only, empty-file add) shows BOTH `0 insertions(+), 0
/// deletions(-)`. Pluralization is git's (`insertion`/`insertions`).
fn stat_summary(rows: &[FileStat]) -> String {
    use std::fmt::Write as _;
    let (mut ins, mut del) = (0usize, 0usize);
    for r in rows {
        if let StatChange::Text { added, deleted } = r.change {
            ins += added;
            del += deleted;
        }
    }
    let mut summary = format!(
        " {} {} changed",
        rows.len(),
        if rows.len() == 1 { "file" } else { "files" }
    );
    if ins != 0 || del == 0 {
        let _ = write!(
            summary,
            ", {ins} insertion{}(+)",
            if ins == 1 { "" } else { "s" }
        );
    }
    if del != 0 || ins == 0 {
        let _ = write!(
            summary,
            ", {del} deletion{}(-)",
            if del == 1 { "" } else { "s" }
        );
    }
    summary
}

/// The `+`/`-` graph for one file. Unscaled: literal `added` `+` then
/// `deleted` `-`. Scaled (git's algorithm): scale the total to the graph
/// width via [`scale_linear`], then split it across `+`/`-`.
fn stat_graph(
    added: usize,
    deleted: usize,
    graph_width: usize,
    max_change: usize,
    scaled: bool,
) -> String {
    let (plus, minus) = if scaled {
        let mut total = scale_linear(added + deleted, graph_width, max_change);
        if total < 2 && added > 0 && deleted > 0 {
            total = 2;
        }
        if added < deleted {
            let a = scale_linear(added, graph_width, max_change);
            (a, total - a)
        } else {
            let d = scale_linear(deleted, graph_width, max_change);
            (total - d, d)
        }
    } else {
        (added, deleted)
    };
    let mut g = "+".repeat(plus);
    g.push_str(&"-".repeat(minus));
    g
}

/// git's diffstat scaling: map `it` changes onto `width` columns. Returns
/// 0 for no change, else at least 1 (so any change shows at least one
/// mark) — `1 + it*(width-1)/max_change`, integer arithmetic, matching
/// git's `scale_linear`.
fn scale_linear(it: usize, width: usize, max_change: usize) -> usize {
    if it == 0 {
        return 0;
    }
    1 + it * (width - 1) / max_change
}

/// Number of decimal digits needed to print `n` (at least 1, for `0`).
fn decimal_width(n: usize) -> usize {
    let mut w = 1;
    let mut v = n;
    while v >= 10 {
        v /= 10;
        w += 1;
    }
    w
}

/// Graph width source: `COLUMNS` when it parses to a positive integer,
/// else git's piped default of 80.
fn terminal_columns() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.trim().parse::<usize>().ok())
        .filter(|&c| c > 0)
        .unwrap_or(80)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_width_counts_digits() {
        assert_eq!(decimal_width(0), 1);
        assert_eq!(decimal_width(9), 1);
        assert_eq!(decimal_width(10), 2);
        assert_eq!(decimal_width(201), 3);
    }

    #[test]
    fn scale_linear_matches_git_formula() {
        // it == 0 → 0; otherwise 1 + it*(width-1)/max_change.
        assert_eq!(scale_linear(0, 47, 201), 0);
        // The values verified against real git: a.txt total 13 → 3,
        // its single deletion → 1; the 201-change file fills the width.
        assert_eq!(scale_linear(13, 47, 201), 3);
        assert_eq!(scale_linear(1, 47, 201), 1);
        assert_eq!(scale_linear(201, 47, 201), 47);
    }

    #[test]
    fn stat_graph_unscaled_is_literal() {
        // When not scaling, the graph is `added` '+' then `deleted` '-'.
        assert_eq!(stat_graph(3, 0, 66, 4, false), "+++");
        assert_eq!(stat_graph(3, 1, 66, 4, false), "+++-");
        assert_eq!(stat_graph(0, 1, 66, 4, false), "-");
    }

    #[test]
    fn stat_graph_scaled_splits_like_git() {
        // a.txt: +12/-1 over graph_width 47, max_change 201 → "++-".
        assert_eq!(stat_graph(12, 1, 47, 201, true), "++-");
        // the max-change file fills the width: 46 '+' + 1 '-'.
        assert_eq!(
            stat_graph(200, 1, 47, 201, true),
            format!("{}-", "+".repeat(46))
        );
    }

    fn row(path: &str, change: StatChange) -> FileStat {
        FileStat {
            path: path.to_string(),
            change,
        }
    }

    fn rendered(rows: &[FileStat]) -> String {
        let mut out = Vec::new();
        render_stat(&mut out, rows).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_binary_row_shows_both_sizes_and_counts_no_line() {
        assert_eq!(
            rendered(&[row(
                "big.bin",
                StatChange::Binary {
                    old_len: 12000,
                    new_len: 15000
                }
            )]),
            " big.bin | Bin 12000 -> 15000 bytes\n \
             1 file changed, 0 insertions(+), 0 deletions(-)\n"
        );
    }

    #[test]
    fn a_text_row_shows_the_count_and_the_graph() {
        assert_eq!(
            rendered(&[row(
                "f.txt",
                StatChange::Text {
                    added: 2,
                    deleted: 1
                }
            )]),
            " f.txt | 3 ++-\n 1 file changed, 2 insertions(+), 1 deletion(-)\n"
        );
    }

    #[test]
    fn a_zero_change_row_has_no_graph() {
        assert_eq!(
            rendered(&[row(
                "run.sh",
                StatChange::Text {
                    added: 0,
                    deleted: 0
                }
            )]),
            " run.sh | 0\n 1 file changed, 0 insertions(+), 0 deletions(-)\n"
        );
    }

    #[test]
    fn a_special_path_is_quoted_and_the_name_column_is_padded() {
        let text = rendered(&[
            row(
                "a\tb",
                StatChange::Text {
                    added: 1,
                    deleted: 0,
                },
            ),
            row(
                "long-name.txt",
                StatChange::Text {
                    added: 1,
                    deleted: 0,
                },
            ),
        ]);
        let quoted = r#""a\tb""#;
        assert!(
            text.starts_with(&format!(" {quoted:<13} | 1 +\n")),
            "{text}"
        );
        assert!(text.contains(" long-name.txt | 1 +\n"), "{text}");
        assert!(
            text.ends_with(" 2 files changed, 2 insertions(+)\n"),
            "{text}"
        );
    }

    #[test]
    fn no_rows_print_nothing() {
        assert_eq!(rendered(&[]), "");
    }
}
