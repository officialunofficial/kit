//! The range tracking behind `kit log -L`, a port of git's line-log.c.
//!
//! A [`RangeSet`] holds the lines of a file that are being followed, as
//! 0-based half-open spans. At each commit, [`map_across`] carries the set
//! from the commit's version of the file to its parent's: a change that
//! overlaps the set is the commit's doing, so the set gives up the lines
//! the change added and takes the lines it replaced; any other change only
//! shifts the lines after it. [`hunks`] renders what a commit did to the
//! set, as git prints it.

use std::ops::Range;

use super::blame::matched_line_spans;
use super::diff::changed_line_spans;

/// A span of lines: 0-based, end excluded.
pub type Span = Range<usize>;

/// A set of lines as sorted spans that neither overlap nor touch, none
/// empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeSet {
    spans: Vec<Span>,
}

impl RangeSet {
    /// The set of the lines of `spans`, in any order. Spans that overlap or
    /// touch merge, and empty ones drop.
    #[must_use]
    pub fn new(spans: impl IntoIterator<Item = Span>) -> Self {
        let mut all: Vec<Span> = spans.into_iter().filter(|s| s.start < s.end).collect();
        all.sort_by_key(|s| (s.start, s.end));
        let mut out: Vec<Span> = Vec::with_capacity(all.len());
        for s in all {
            match out.last_mut() {
                Some(last) if s.start <= last.end => last.end = last.end.max(s.end),
                _ => out.push(s),
            }
        }
        Self { spans: out }
    }

    /// The spans, in order.
    #[must_use]
    pub fn spans(&self) -> &[Span] {
        &self.spans
    }

    /// Whether the set holds no line.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// The lines of either set.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self::new(self.spans.iter().chain(&other.spans).cloned())
    }

    /// The lines of `self` outside every span of `cut`, which is sorted,
    /// as spans in order. A port of git's `range_set_difference`: an empty
    /// cut inside a span still splits it, so that [`shift`] moves the part
    /// after a deletion on its own.
    fn difference(&self, cut: &[Span]) -> Vec<Span> {
        let mut out = Vec::new();
        let mut j = 0;
        for span in &self.spans {
            let (mut start, end) = (span.start, span.end);
            while start < end {
                while j < cut.len() && start >= cut[j].end {
                    j += 1;
                }
                // git tests `end < start` here, which never ends for a cut
                // that starts right at the end of the span.
                if j >= cut.len() || end <= cut[j].start {
                    out.push(start..end);
                    break;
                }
                if start >= cut[j].start {
                    start = cut[j].end;
                } else if end > cut[j].start {
                    out.push(start..cut[j].start);
                    start = cut[j].end;
                }
            }
        }
        out
    }
}

/// One changed region between a parent's version of a file and a commit's,
/// with no context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The lines of the parent's version that the change removes.
    pub parent: Span,
    /// The lines of the commit's version that the change adds.
    pub target: Span,
}

/// The changes from `parent` to `target`, in order.
#[must_use]
pub fn changes(parent: &[u8], target: &[u8]) -> Vec<Change> {
    matched_line_spans(parent, target)
        .into_iter()
        .map(|(parent, target)| Change { parent, target })
        .collect()
}

/// Do two spans share a line? An empty span strictly inside the other
/// counts, as in git.
fn overlaps(a: &Span, b: &Span) -> bool {
    !(a.end <= b.start || b.end <= a.start)
}

/// Carry `ranges`, lines of a commit's version of a file, to its parent's
/// version across `changes`. The result is the parent's set and the
/// changes that touch `ranges`, which are the commit's doing.
#[must_use]
pub fn map_across(ranges: &RangeSet, changes: &[Change]) -> (RangeSet, Vec<Change>) {
    let touched = touched(ranges, changes);
    let targets: Vec<Span> = touched.iter().map(|c| c.target.clone()).collect();
    let rest = ranges.difference(&targets);
    let shifted = shift(&rest, changes);
    let parents = RangeSet::new(touched.iter().map(|c| c.parent.clone()));
    (shifted.union(&parents), touched)
}

/// The changes whose target side overlaps a span of `ranges`. A port of
/// git's `diff_ranges_filter_touched`.
fn touched(ranges: &RangeSet, changes: &[Change]) -> Vec<Change> {
    let spans = ranges.spans();
    let mut out = Vec::new();
    if spans.is_empty() {
        return out;
    }
    let mut j = 0;
    for change in changes {
        while change.target.start > spans[j].end {
            j += 1;
            if j == spans.len() {
                return out;
            }
        }
        if overlaps(&change.target, &spans[j]) {
            out.push(change.clone());
        }
    }
    out
}

/// Move each span, of spans in order, by the lines that the changes before
/// it add and remove. A port of git's `range_set_shift_diff`.
fn shift(spans: &[Span], changes: &[Change]) -> RangeSet {
    let mut out = Vec::with_capacity(spans.len());
    let mut j = 0;
    // Lines gained in the parent minus lines gained in the commit, so far.
    let (mut plus, mut minus) = (0usize, 0usize);
    for span in spans {
        while j < changes.len() && span.start >= changes[j].target.start {
            plus += changes[j].parent.len();
            minus += changes[j].target.len();
            j += 1;
        }
        let at = |n: usize| (n + plus).saturating_sub(minus);
        out.push(at(span.start)..at(span.end));
    }
    RangeSet::new(out)
}

/// One line of a hunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HunkLine {
    /// `b' '` for a line of both versions, `b'-'` for a removed line and
    /// `b'+'` for an added one.
    pub origin: u8,
    /// The line, without its newline.
    pub text: Vec<u8>,
    /// Whether the line ends with a newline.
    pub newline: bool,
}

/// What a commit did to one span of the followed lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeHunk {
    /// The first line of the span in the parent, 1-based, as git prints
    /// it: 0 when the parent has no lines.
    pub old_start: usize,
    /// The number of lines of the span in the parent.
    pub old_lines: usize,
    /// The first line of the span in the commit, 1-based.
    pub new_start: usize,
    /// The number of lines of the span in the commit.
    pub new_lines: usize,
    /// The lines of the span: context, removed and added.
    pub lines: Vec<HunkLine>,
    /// The function line that git prints after the hunk header, or empty
    /// for none.
    pub func: Vec<u8>,
}

/// git's default function line rule: a line that starts with a letter,
/// `_` or `$`, cut at 80 bytes, with trailing white space removed.
fn function_line(text: &[u8]) -> Option<Vec<u8>> {
    let first = *text.first()?;
    if !(first.is_ascii_alphabetic() || first == b'_' || first == b'$') {
        return None;
    }
    let mut len = text.len().min(80);
    while len > 0 && matches!(text[len - 1], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        len -= 1;
    }
    Some(text[..len].to_vec())
}

/// The hunks of the standard diff from `parent` to `target` with `context`
/// lines of context, each as the commit-side lines it covers and the
/// function line of its header. A port of the hunk grouping and the
/// function line search of git's `xdl_emit_diff`: each search goes up from
/// the line above the hunk's context to the line above the previous hunk's
/// context, and a search that finds nothing keeps the previous name.
fn standard_hunk_funcs(
    p_lines: &[(&[u8], bool)],
    t_len: usize,
    spans: &[(Span, Span)],
    context: usize,
) -> Vec<(Span, Vec<u8>)> {
    let mut out = Vec::new();
    let mut func = Vec::new();
    // The line above the previous hunk's context; `None` before the first.
    let mut limit: Option<usize> = None;
    let mut i = 0;
    while i < spans.len() {
        let mut last = i;
        while last + 1 < spans.len() && spans[last + 1].0.start - spans[last].0.end <= 2 * context {
            last += 1;
        }
        let (first, end) = (&spans[i], &spans[last]);
        let s1 = first.0.start.saturating_sub(context);
        let s2 = first.1.start.saturating_sub(context);
        let after = context
            .min(p_lines.len().saturating_sub(end.0.end))
            .min(t_len.saturating_sub(end.1.end));
        let e2 = end.1.end + after;
        if let Some(start) = s1.checked_sub(1) {
            let stop = limit.map_or(0, |l| l + 1);
            if let Some(found) = (stop..=start)
                .rev()
                .find_map(|l| p_lines.get(l).and_then(|(text, _)| function_line(text)))
            {
                func = found;
            }
        }
        limit = s1.checked_sub(1);
        out.push((s2..e2, func.clone()));
        i = last + 1;
    }
    out
}

/// The lines of `text`, each with whether it ends with a newline.
fn split(text: &[u8]) -> Vec<(&[u8], bool)> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(i) = rest.iter().position(|&b| b == b'\n') {
            out.push((&rest[..i], true));
            rest = &rest[i + 1..];
        } else {
            out.push((rest, false));
            rest = &[];
        }
    }
    out
}

/// The hunks of the spans of `ranges`, the commit's set, for the changes
/// it `touched`, between the parent's version `parent` and the commit's
/// version `target`. A port of git's `dump_diff_hacky_one`: like git, a
/// change that two spans share prints under the first one only.
#[must_use]
pub fn hunks(
    ranges: &RangeSet,
    touched: &[Change],
    parent: &[u8],
    target: &[u8],
) -> Vec<RangeHunk> {
    let (p_lines, t_lines) = (split(parent), split(target));
    let line = |lines: &[(&[u8], bool)], origin: u8, n: usize| {
        let (text, newline) = lines.get(n).copied().unwrap_or((&[], true));
        HunkLine {
            origin,
            text: text.to_vec(),
            newline,
        }
    };
    // git prints the hunks of the standard diff clipped to the ranges, with
    // the largest span as the context when it is more than 3 lines.
    let context = ranges
        .spans()
        .iter()
        .map(ExactSizeIterator::len)
        .fold(3, usize::max);
    let standard = standard_hunk_funcs(
        &p_lines,
        t_lines.len(),
        &changed_line_spans(parent, target),
        context,
    );
    let mut out = Vec::new();
    let mut j = 0;
    for span in ranges.spans() {
        let (t_start, t_end) = (span.start, span.end);
        while j < touched.len() && touched[j].target.end < t_start {
            j += 1;
        }
        if j == touched.len() || touched[j].target.start > t_end {
            continue;
        }
        let mut j_last = j;
        while j_last < touched.len() && touched[j_last].target.start < t_end {
            j_last += 1;
        }
        if j_last > j {
            j_last -= 1;
        }
        let (first, last) = (&touched[j], &touched[j_last]);
        let at = first.target.start;
        let func = standard
            .iter()
            .rev()
            .find(|(cover, _)| cover.start <= at)
            .map(|(_, f)| f.clone())
            .unwrap_or_default();
        let p_start = if t_start < first.target.start {
            first
                .parent
                .start
                .saturating_sub(first.target.start - t_start)
        } else {
            first.parent.start
        };
        let p_end = if t_end > last.target.end {
            last.parent.end + (t_end - last.target.end)
        } else {
            last.parent.end
        };
        // git takes the old start from the old line where the standard diff
        // stands, so an empty span at the top is `-1,0`, and `-0,0` only
        // when the file did not exist.
        let old_start = if p_lines.is_empty() { 0 } else { p_start + 1 };
        let mut lines = Vec::new();
        let mut t_cur = t_start;
        while j < touched.len() && touched[j].target.start < t_end {
            let change = &touched[j];
            while t_cur < change.target.start {
                lines.push(line(&t_lines, b' ', t_cur));
                t_cur += 1;
            }
            for k in change.parent.clone() {
                lines.push(line(&p_lines, b'-', k));
            }
            while t_cur < change.target.end && t_cur < t_end {
                lines.push(line(&t_lines, b'+', t_cur));
                t_cur += 1;
            }
            j += 1;
        }
        while t_cur < t_end {
            lines.push(line(&t_lines, b' ', t_cur));
            t_cur += 1;
        }
        out.push(RangeHunk {
            old_start,
            old_lines: p_end.saturating_sub(p_start),
            new_start: t_start + 1,
            new_lines: t_end - t_start,
            lines,
            func,
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::single_range_in_vec_init)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn set(spans: &[Span]) -> RangeSet {
        RangeSet::new(spans.iter().cloned())
    }

    fn lines_of(r: &RangeSet) -> BTreeSet<usize> {
        r.spans().iter().flat_map(Clone::clone).collect()
    }

    #[test]
    fn spans_merge_when_they_overlap_or_touch() {
        assert_eq!(set(&[3..5, 0..1, 1..2, 4..7, 9..9]).spans(), [0..2, 3..7]);
    }

    #[test]
    fn an_insertion_above_shifts_the_range() {
        let ch = changes(b"a\nb\nc\n", b"x\ny\na\nb\nc\n");
        let (parent, touched) = map_across(&set(&[3..4]), &ch);
        assert!(touched.is_empty());
        assert_eq!(parent.spans(), [1..2]);
    }

    #[test]
    fn an_edit_inside_takes_the_old_lines() {
        let ch = changes(b"a\nb\nc\nd\n", b"a\nB\nB2\nc\nd\n");
        let (parent, touched) = map_across(&set(&[0..3]), &ch);
        assert_eq!(touched.len(), 1);
        assert_eq!(parent.spans(), [0..2]);
        let h = hunks(
            &set(&[0..3]),
            &touched,
            b"a\nb\nc\nd\n",
            b"a\nB\nB2\nc\nd\n",
        );
        assert_eq!(
            (
                h[0].old_start,
                h[0].old_lines,
                h[0].new_start,
                h[0].new_lines
            ),
            (1, 2, 1, 3)
        );
        let text: Vec<String> = h[0]
            .lines
            .iter()
            .map(|l| format!("{}{}", l.origin as char, String::from_utf8_lossy(&l.text)))
            .collect();
        assert_eq!(text, [" a", "-b", "+B", "+B2"]);
    }

    /// The hunks of `ranges` for the change from `parent` to `target`.
    fn hunks_of(ranges: &[Span], parent: &[u8], target: &[u8]) -> Vec<RangeHunk> {
        let (_, touched) = map_across(&set(ranges), &changes(parent, target));
        hunks(&set(ranges), &touched, parent, target)
    }

    #[test]
    fn a_hunk_names_the_function_line_above_it() {
        // git looks for the line above the context of the standard diff,
        // with the range's span as the context when it is more than 3.
        let parent = b"int f()\n{\n\ta;\n\tb;\n\tc;\n\td;\n\te;\n}\n";
        let target = b"int f()\n{\n\ta;\n\tb;\n\tc;\n\td;\n\tE;\n}\n";
        let h = hunks_of(&[6..7], parent, target);
        assert_eq!(h[0].func, b"int f()");
        // A context that reaches the top of the file leaves nothing above.
        let h = hunks_of(&[0..7], parent, target);
        assert!(h[0].func.is_empty());
    }

    #[test]
    fn a_later_hunk_keeps_the_function_line_when_none_is_above_it() {
        // Two hunks of the standard diff: the second looks only down to the
        // line above the first one's context, finds nothing, and keeps the
        // first one's name, as git's xdiff does.
        let mut parent = b"A\n".to_vec();
        for i in 1..14 {
            parent.extend_from_slice(format!("\tx{i}\n").as_bytes());
        }
        let target = String::from_utf8(parent.clone())
            .unwrap()
            .replace("\tx4\n", "\tX4\n")
            .replace("\tx12\n", "\tX12\n");
        let h = hunks_of(&[4..5, 12..13], &parent, target.as_bytes());
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].func, b"A");
        assert_eq!(h[1].func, b"A");
    }

    #[test]
    fn a_function_line_is_cut_at_80_bytes_and_trimmed() {
        let long = format!("f{}  ", "x".repeat(100));
        let parent = format!("{long}\n\ta\n\tb\n\tc\n\td\n");
        let target = parent.replace("\td\n", "\tD\n");
        let h = hunks_of(&[4..5], parent.as_bytes(), target.as_bytes());
        assert_eq!(h[0].func, long.as_bytes()[..80].to_vec());
        let short = "g()   \n\ta\n\tb\n\tc\n\td\n";
        let h = hunks_of(
            &[4..5],
            short.as_bytes(),
            short.replace("\td", "\tD").as_bytes(),
        );
        assert_eq!(h[0].func, b"g()");
    }

    #[test]
    fn an_insertion_at_the_top_counts_from_the_first_old_line() {
        // git takes the old start from the line the standard diff is at, so
        // only a file that did not exist starts at 0.
        let h = hunks_of(&[0..1], b"a\nb\n", b"x\na\nb\n");
        assert_eq!((h[0].old_start, h[0].old_lines, h[0].new_start), (1, 0, 1));
        let h = hunks_of(&[1..2], b"a\nb\n", b"a\nx\nb\n");
        assert_eq!((h[0].old_start, h[0].old_lines, h[0].new_start), (2, 0, 2));
    }

    /// Each hunk as its header numbers and its lines, origin first.
    fn shapes(h: &[RangeHunk]) -> Vec<(usize, usize, usize, usize, Vec<String>)> {
        h.iter()
            .map(|h| {
                let lines = h
                    .lines
                    .iter()
                    .map(|l| format!("{}{}", l.origin as char, String::from_utf8_lossy(&l.text)))
                    .collect();
                (h.old_start, h.old_lines, h.new_start, h.new_lines, lines)
            })
            .collect()
    }

    #[test]
    fn a_change_that_two_ranges_share_prints_under_each() {
        // git clips the standard diff to each range in turn, so the lines
        // of one creation show under both ranges.
        let h = hunks_of(
            &[1..3, 4..5],
            b"",
            b"header\nfn f() {\n    one();\n}\ntail\n",
        );
        assert_eq!(
            shapes(&h),
            [
                (0, 0, 2, 2, vec!["+fn f() {".into(), "+    one();".into()]),
                (0, 0, 5, 1, vec!["+tail".into()]),
            ]
        );
    }

    #[test]
    fn a_removal_next_to_a_range_prints_with_it() {
        // A removal just above the range's first line is flushed into the
        // range, and so is one just below its last line.
        let h = hunks_of(&[1..2], b"a\nb\nc\n", b"a\nc\n");
        assert_eq!(shapes(&h), [(2, 2, 2, 1, vec!["-b".into(), " c".into()])]);
        let h = hunks_of(&[0..1], b"a\nb\nc\n", b"a\nc\n");
        assert_eq!(shapes(&h), [(1, 2, 1, 1, vec![" a".into(), "-b".into()])]);
    }

    #[test]
    fn a_range_with_only_context_prints_nothing() {
        // A change outside the range brings context into it, which git
        // drops.
        let h = hunks_of(&[0..1], b"a\nb\nc\n", b"a\nb\nC\n");
        assert!(h.is_empty());
    }

    #[test]
    fn a_repeated_line_aligns_as_blame_does() {
        // Blame matches the old `l5` to the first new `l5`, so the change is
        // the insertion of `l0` above it and of the second `l5` below.
        let c = changes(b"l5\n", b"l0\nl5\nl5\n");
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].parent.clone(), c[0].target.clone()), (0..0, 0..1));
        assert_eq!((c[1].parent.clone(), c[1].target.clone()), (1..1, 2..3));
    }

    #[test]
    fn a_creation_empties_the_range() {
        let ch = changes(b"", b"a\nb\n");
        let (parent, touched) = map_across(&set(&[1..2]), &ch);
        assert!(parent.is_empty());
        let h = hunks(&set(&[1..2]), &touched, b"", b"a\nb\n");
        assert_eq!(
            (
                h[0].old_start,
                h[0].old_lines,
                h[0].new_start,
                h[0].new_lines
            ),
            (0, 0, 2, 1)
        );
    }

    /// The parent line each commit line comes from, by walking the changes.
    fn alignment(changes: &[Change], target_len: usize) -> Vec<Option<usize>> {
        let mut out = vec![None; target_len];
        let (mut p, mut t) = (0, 0);
        for c in changes {
            while t < c.target.start {
                out[t] = Some(p);
                p += 1;
                t += 1;
            }
            p = c.parent.end;
            t = c.target.end;
        }
        while t < target_len {
            out[t] = Some(p);
            p += 1;
            t += 1;
        }
        out
    }

    fn text(lines: &[u8]) -> Vec<u8> {
        lines
            .iter()
            .flat_map(|n| format!("l{n}\n").into_bytes())
            .collect()
    }

    proptest! {
        /// The set operations agree with sets of lines.
        #[test]
        fn set_operations_match_a_model(
            a in proptest::collection::vec((0usize..30, 0usize..6), 0..6),
            b in proptest::collection::vec((0usize..30, 0usize..6), 0..6),
        ) {
            let a = RangeSet::new(a.iter().map(|&(s, l)| s..s + l));
            let b = RangeSet::new(b.iter().map(|&(s, l)| s..s + l));
            let (la, lb) = (lines_of(&a), lines_of(&b));
            prop_assert_eq!(lines_of(&a.union(&b)), la.union(&lb).copied().collect::<BTreeSet<_>>());
            prop_assert_eq!(lines_of(&RangeSet::new(a.difference(b.spans()))), la.difference(&lb).copied().collect::<BTreeSet<_>>());
            for w in a.spans().windows(2) {
                prop_assert!(w[0].end < w[1].start);
            }
        }

        /// Mapping across a diff keeps each untouched line at its aligned
        /// parent line, adds the parent side of each touched change, and
        /// touches only changes that overlap the set.
        #[test]
        fn mapping_follows_the_alignment(
            parent in proptest::collection::vec(0u8..5, 0..12),
            target in proptest::collection::vec(0u8..5, 1..12),
            start in 0usize..12,
            len in 1usize..5,
        ) {
            let (p, t) = (text(&parent), text(&target));
            let start = start.min(target.len() - 1);
            let end = (start + len).min(target.len());
            let ranges = set(&[start..end]);
            let ch = changes(&p, &t);
            let (mapped, touched) = map_across(&ranges, &ch);
            let align = alignment(&ch, target.len());
            let mut want: BTreeSet<usize> = BTreeSet::new();
            for (line, parent_line) in align.iter().enumerate().take(end).skip(start) {
                if touched.iter().all(|c| !c.target.contains(&line)) {
                    want.insert(parent_line.unwrap());
                }
            }
            for c in &touched {
                want.extend(c.parent.clone());
                prop_assert!(overlaps(&c.target, &(start..end)));
            }
            for c in &ch {
                if !touched.contains(c) {
                    prop_assert!(!overlaps(&c.target, &(start..end)));
                }
            }
            prop_assert_eq!(lines_of(&mapped), want);
            // Every hunk line is a line of its version, and each touched
            // change's lines appear.
            let h = hunks(&ranges, &touched, &p, &t);
            prop_assert_eq!(h.is_empty(), touched.is_empty());
        }
    }
}
