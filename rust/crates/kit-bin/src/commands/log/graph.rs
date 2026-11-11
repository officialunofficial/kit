//! The ASCII commit graph of `kit log --graph`.
//!
//! [`Graph`] takes the commits in output order, each with its visible parents.
//! For each commit it gives the text to put in the left margin. A column holds
//! the commit that the line above it waits for, so a column is one open
//! branch of the history. The number of columns is the number of branches
//! that are open at that point, and it never passes [`MAX_COLUMNS`].
//!
//! The marks are `*` for a commit, `|` for a column, `/` where a column joins
//! one on its left or shifts left, and `\` where a merge opens a column on its
//! right. Each cell takes two characters, so column `k` starts at `2 * k`.

use kit_core::Hash;

/// The most columns the graph draws. A history with more open branches is an
/// error, so the margin and the state stay small.
pub(super) const MAX_COLUMNS: usize = 1024;

/// The history has more than [`MAX_COLUMNS`] open branches.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct TooWide;

/// The margin text of one commit.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Row {
    /// Lines of graph marks that come before the commit. They join columns
    /// that wait for this commit.
    pub(super) before: Vec<String>,
    /// The margin of the first line of the commit, with the mark `*` and a
    /// space after it.
    pub(super) first: String,
    /// The margin of every other line of the commit. A commit without a parent
    /// leaves its own column blank in it.
    pub(super) rest: String,
    /// Lines of graph marks that come after the commit. They open the columns
    /// of the parents after the first, and shift the columns right of a
    /// commit that has no parent.
    pub(super) after: Vec<String>,
}

/// The open columns of the graph. Each holds the commit that it waits for.
#[derive(Debug, Default)]
pub(super) struct Graph {
    columns: Vec<Hash>,
}

impl Graph {
    /// Draw `commit`, whose parents in the output are `parents`.
    ///
    /// # Errors
    /// [`TooWide`] when the graph would have more than [`MAX_COLUMNS`]
    /// columns.
    pub(super) fn push(&mut self, commit: &Hash, parents: &[Hash]) -> Result<Row, TooWide> {
        let mut before = Vec::new();
        let mut after = Vec::new();
        // The commit takes the first column that waits for it, or a new one
        // when it is a tip.
        let column = if let Some(column) = self.columns.iter().position(|c| c == commit) {
            column
        } else {
            self.columns.push(*commit);
            self.columns.len() - 1
        };
        // Each later column that waits for the commit joins this one.
        while let Some(joined) =
            (column + 1..self.columns.len()).find(|&k| self.columns[k] == *commit)
        {
            before.push(shift_line(self.columns.len(), joined, true));
            self.columns.remove(joined);
        }
        let first: String = (0..self.columns.len())
            .map(|k| if k == column { "* " } else { "| " })
            .collect();

        // A commit without a parent ends its column, and the lines of its text
        // leave that column blank.
        let rest = match parents.split_first() {
            None => {
                let width = self.columns.len();
                let rest = (0..width)
                    .map(|k| if k == column { "  " } else { "| " })
                    .collect();
                self.columns.remove(column);
                if column < self.columns.len() {
                    after.push(shift_line(width, column, false));
                }
                rest
            }
            Some((first_parent, others)) => {
                self.columns[column] = *first_parent;
                if !others.is_empty() {
                    let width = self.columns.len();
                    let at = column + 1;
                    self.columns.splice(at..at, others.iter().copied());
                    after.push(merge_line(width, column, others.len()));
                }
                "| ".repeat(self.columns.len())
            }
        };
        if self.columns.len() > MAX_COLUMNS {
            return Err(TooWide);
        }
        Ok(Row {
            before,
            first,
            rest,
            after,
        })
    }
}

/// A line that moves the columns from `at` rightward one cell to the left.
/// With `join`, column `at` ends on the column to its left, and it gets a
/// `/`. Without it, column `at` ends and gets no mark.
fn shift_line(width: usize, at: usize, join: bool) -> String {
    let mut line = vec![' '; 2 * width];
    for k in 0..width {
        if k < at {
            line[2 * k] = '|';
        } else if k > at || join {
            line[2 * k - 1] = '/';
        }
    }
    finish(line)
}

/// A line that opens `opened` columns after column `at`. `width` is the
/// number of columns before them. A column right of `at` moves right by
/// `opened`.
fn merge_line(width: usize, at: usize, opened: usize) -> String {
    let mut line = vec![' '; 2 * (width + opened)];
    for k in 0..=at {
        line[2 * k] = '|';
    }
    for n in 1..=opened {
        line[2 * (at + n) - 1] = '\\';
    }
    for k in at + 1..width {
        line[2 * (k + opened)] = '|';
    }
    finish(line)
}

fn finish(line: Vec<char>) -> String {
    let line: String = line.into_iter().collect();
    line.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash {
        [n; 32]
    }

    /// The graph lines of a history. Each commit is `(id, parents)`, and its
    /// text is its id as a letter.
    fn draw(history: &[(u8, &[u8])]) -> Vec<String> {
        let mut graph = Graph::default();
        let mut lines = Vec::new();
        for (id, parents) in history {
            let parents: Vec<Hash> = parents.iter().map(|p| h(*p)).collect();
            let row = graph.push(&h(*id), &parents).unwrap();
            lines.extend(row.before);
            lines.push(format!("{}{}", row.first, *id as char));
            lines.extend(row.after);
        }
        lines
    }

    const A: u8 = b'a';
    const B: u8 = b'b';
    const C: u8 = b'c';
    const D: u8 = b'd';
    const M: u8 = b'm';
    const R: u8 = b'r';
    const S: u8 = b's';
    const X: u8 = b'x';

    #[test]
    fn linear_history_is_one_column() {
        let lines = draw(&[(C, &[B]), (B, &[A]), (A, &[])]);
        assert_eq!(lines, ["* c", "* b", "* a"]);
    }

    #[test]
    fn a_root_commit_has_no_column_after_it() {
        let mut graph = Graph::default();
        let row = graph.push(&h(R), &[]).unwrap();
        assert_eq!(row.first, "* ");
        assert_eq!(row.rest, "  ");
        assert!(row.before.is_empty() && row.after.is_empty());
        assert!(graph.columns.is_empty());
    }

    #[test]
    fn a_commit_with_a_parent_keeps_its_column_for_the_lines_below() {
        let mut graph = Graph::default();
        let row = graph.push(&h(B), &[h(A)]).unwrap();
        assert_eq!(row.rest, "| ");
    }

    #[test]
    fn a_merge_opens_a_column_and_the_branches_join_again() {
        // m merges a and s. Both come from r.
        let lines = draw(&[(M, &[A, S]), (A, &[R]), (S, &[R]), (R, &[])]);
        assert_eq!(lines, ["* m", "|\\", "* | a", "| * s", "|/", "* r"]);
    }

    #[test]
    fn two_parallel_branches_from_every_tip_join_at_their_base() {
        // `log --all` starts at the tips c and d. Both come from a.
        let lines = draw(&[(C, &[B]), (D, &[A]), (B, &[A]), (A, &[])]);
        assert_eq!(lines, ["* c", "| * d", "* | b", "|/", "* a"]);
    }

    #[test]
    fn an_octopus_merge_opens_one_column_per_extra_parent() {
        let lines = draw(&[(M, &[A, B, C]), (A, &[R]), (B, &[R]), (C, &[R]), (R, &[])]);
        assert_eq!(
            lines,
            [
                "* m", "|\\ \\", "* | | a", "| * | b", "| | * c", "|/ /", "|/", "* r"
            ]
        );
    }

    #[test]
    fn a_root_left_of_another_column_shifts_that_column() {
        // a waits for r, b waits for s. r is a root and sits left of b.
        let lines = draw(&[(A, &[R]), (B, &[S]), (R, &[]), (S, &[])]);
        assert_eq!(lines, ["* a", "| * b", "* | r", " /", "* s"]);
    }

    #[test]
    fn a_merge_left_of_another_column_moves_that_column_right() {
        // x is open on the right while m opens a column next to its own.
        let mut graph = Graph::default();
        graph.push(&h(X), &[h(R)]).unwrap();
        let row = graph.push(&h(M), &[h(A), h(S)]).unwrap();
        assert_eq!(row.first, "| * ");
        assert_eq!(row.after, ["| |\\"]);
        assert_eq!(graph.columns, [h(R), h(A), h(S)]);
        let row = graph.push(&h(R), &[]).unwrap();
        assert_eq!(row.first, "* | | ");
    }

    #[test]
    fn a_column_right_of_a_merge_is_drawn_after_the_new_columns() {
        let mut graph = Graph::default();
        graph.push(&h(M), &[h(A), h(S)]).unwrap();
        graph.push(&h(X), &[h(R)]).unwrap();
        // Columns: a, s, r. Merge a again with a parent on the right.
        let row = graph.push(&h(A), &[h(B), h(C)]).unwrap();
        assert_eq!(row.first, "* | | ");
        assert_eq!(row.after, ["|\\  | |"]);
    }

    #[test]
    fn a_history_with_too_many_open_branches_is_an_error() {
        fn id(n: usize) -> Hash {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&(n as u64).to_le_bytes());
            hash
        }
        let mut graph = Graph::default();
        // Each tip waits for a parent of its own, so no column joins.
        let parent = |n: usize| id(n + 10 * MAX_COLUMNS);
        for n in 0..MAX_COLUMNS {
            assert!(graph.push(&id(n), &[parent(n)]).is_ok());
        }
        assert_eq!(
            graph.push(&id(MAX_COLUMNS), &[parent(MAX_COLUMNS)]).err(),
            Some(TooWide)
        );
    }
}
