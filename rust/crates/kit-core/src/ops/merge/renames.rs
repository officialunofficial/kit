//! Renames in the three-way merge.
//!
//! Before the path-by-path merge, each side is compared with the base and
//! its renames are detected with the similarity detection of `diff`. A file
//! that one side renamed and the other side kept moves to the new path in
//! the base and in the side that kept it, so the path-by-path merge sees
//! one file at one path on all three sides and merges its content there.
//!
//! A rename against a delete, and two renames of one file to different
//! paths, are conflicts. The path-by-path merge already keeps each renamed
//! file at its new path, so these conflicts are reported beside it.
//!
//! A rename is not followed when the side that kept the file also holds the
//! new path, or a file where the new path needs a directory: the paths then
//! merge as they would without rename detection.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::hash::Hash;
use crate::object::{EntryMode, TreeEntry};
use crate::ops::diff::{DiffEntry, DiffKind, diff_trees};
use crate::ops::similarity::{RenameOptions, detect_renames};
use crate::store::{MAX_TREE_DEPTH, ObjectSink, ObjectSource, StoreError};

use super::{Conflict, ConflictKind, RenameConflict, load_entries, put_tree};

/// The trees to merge path by path, and the rename conflicts to report.
pub(super) struct Prepared {
    pub base: Option<Hash>,
    pub ours: Option<Hash>,
    pub theirs: Option<Hash>,
    pub conflicts: Vec<Conflict>,
}

/// One side's changes against the base.
struct Changes {
    /// Renames, by the old path.
    renames: HashMap<String, DiffEntry>,
    /// Every other change, by path.
    other: HashMap<String, DiffEntry>,
    /// The new paths of the renames.
    destinations: HashSet<String>,
}

impl Changes {
    fn read<S: ObjectSource + ?Sized>(
        store: &S,
        base: Option<Hash>,
        side: Option<Hash>,
        options: &RenameOptions,
    ) -> Result<Self, StoreError> {
        let mut entries = diff_trees(store, base, side)?.entries;
        detect_renames(store, &mut entries, options)?;
        let mut changes = Changes {
            renames: HashMap::new(),
            other: HashMap::new(),
            destinations: HashSet::new(),
        };
        for e in entries {
            match (e.kind, &e.old_path) {
                (DiffKind::Renamed, Some(old)) => {
                    changes.destinations.insert(e.path.clone());
                    changes.renames.insert(old.clone(), e);
                }
                _ => {
                    changes.other.insert(e.path.clone(), e);
                }
            }
        }
        Ok(changes)
    }

    /// Whether this side holds `path`, which the base does not hold.
    fn adds(&self, path: &str) -> bool {
        self.destinations.contains(path)
            || self
                .other
                .get(path)
                .is_some_and(|e| e.kind == DiffKind::Added)
    }

    /// Whether this side deleted `path` of the base without renaming it.
    fn deletes(&self, path: &str) -> bool {
        self.other
            .get(path)
            .is_some_and(|e| e.kind == DiffKind::Removed)
    }

    /// The entry this side holds at `path` of the base, which it kept:
    /// its new content when it changed the file, else the base entry.
    fn kept(&self, path: &str, base: (EntryMode, Hash)) -> (EntryMode, Hash) {
        match self.other.get(path) {
            Some(e) => match (e.new_mode, e.new_hash) {
                (Some(mode), Some(hash)) => (mode, hash),
                _ => base,
            },
            None => base,
        }
    }
}

/// An entry to put at a path, or `None` to remove the path.
type Leaf = Option<(EntryMode, Hash)>;

/// A change to one path of a tree.
type Edit = (String, Leaf);

/// An [`Edit`] with its path split into components.
type SplitEdit<'a> = (Vec<&'a str>, Leaf);

/// Detect the renames of each side and move the files they rename, as the
/// module comment describes. Without a base nothing is renamed.
pub(super) fn prepare<S: ObjectSource + ObjectSink + ?Sized>(
    store: &S,
    base: Option<Hash>,
    ours: Option<Hash>,
    theirs: Option<Hash>,
    options: &RenameOptions,
) -> Result<Prepared, StoreError> {
    let unchanged = Prepared {
        base,
        ours,
        theirs,
        conflicts: Vec::new(),
    };
    if base.is_none() {
        return Ok(unchanged);
    }
    let ours_changes = Changes::read(store, base, ours, options)?;
    let theirs_changes = Changes::read(store, base, theirs, options)?;
    if ours_changes.renames.is_empty() && theirs_changes.renames.is_empty() {
        return Ok(unchanged);
    }

    let mut base_edits: Vec<Edit> = Vec::new();
    let mut ours_edits: Vec<Edit> = Vec::new();
    let mut theirs_edits: Vec<Edit> = Vec::new();
    let mut conflicts = Vec::new();

    let mut sources: Vec<&String> = ours_changes
        .renames
        .keys()
        .chain(theirs_changes.renames.keys())
        .collect();
    sources.sort();
    sources.dedup();
    for from in sources {
        match (
            ours_changes.renames.get(from),
            theirs_changes.renames.get(from),
        ) {
            (Some(o), Some(t)) if o.path == t.path => {
                if !blocked(store, base, &o.path)? {
                    move_base(&mut base_edits, from, o);
                }
            }
            (Some(o), Some(t)) => {
                conflicts.push(rename_conflict(o, Side::Ours, Some(&t.path)));
                conflicts.push(rename_conflict(t, Side::Theirs, Some(&o.path)));
            }
            (Some(o), None) => {
                follow(
                    store,
                    from,
                    o,
                    Side::Ours,
                    &theirs_changes,
                    (base, theirs),
                    (&mut base_edits, &mut theirs_edits),
                    &mut conflicts,
                )?;
            }
            (None, Some(t)) => {
                follow(
                    store,
                    from,
                    t,
                    Side::Theirs,
                    &ours_changes,
                    (base, ours),
                    (&mut base_edits, &mut ours_edits),
                    &mut conflicts,
                )?;
            }
            (None, None) => {}
        }
    }

    Ok(Prepared {
        base: edit_root(store, base, &base_edits)?,
        ours: edit_root(store, ours, &ours_edits)?,
        theirs: edit_root(store, theirs, &theirs_edits)?,
        conflicts,
    })
}

#[derive(Clone, Copy)]
enum Side {
    Ours,
    Theirs,
}

/// Follow the rename `renamed` of `from` that only `side` made, into the
/// other side, whose changes are `other`.
#[allow(clippy::too_many_arguments)]
fn follow<S: ObjectSource + ?Sized>(
    store: &S,
    from: &str,
    renamed: &DiffEntry,
    side: Side,
    other: &Changes,
    (base, other_root): (Option<Hash>, Option<Hash>),
    (base_edits, other_edits): (&mut Vec<Edit>, &mut Vec<Edit>),
    conflicts: &mut Vec<Conflict>,
) -> Result<(), StoreError> {
    let (Some(mode), Some(hash)) = (renamed.old_mode, renamed.old_hash) else {
        return Ok(());
    };
    if other.deletes(from) {
        conflicts.push(rename_conflict(renamed, side, None));
        return Ok(());
    }
    let to = &renamed.path;
    if other.adds(to) || blocked(store, base, to)? || blocked(store, other_root, to)? {
        return Ok(());
    }
    move_base(base_edits, from, renamed);
    other_edits.push((from.to_owned(), None));
    other_edits.push((to.clone(), Some(other.kept(from, (mode, hash)))));
    Ok(())
}

/// Move the base entry of `from` to the new path of `renamed`.
fn move_base(edits: &mut Vec<Edit>, from: &str, renamed: &DiffEntry) {
    if let (Some(mode), Some(hash)) = (renamed.old_mode, renamed.old_hash) {
        edits.push((from.to_owned(), None));
        edits.push((renamed.path.clone(), Some((mode, hash))));
    }
}

/// The conflict at the new path of a rename that `side` made, against a
/// delete (`other_path` is `None`) or a rename to `other_path`. It has the
/// shape of a delete/modify conflict: the base content, and the renamed
/// file on `side` only.
fn rename_conflict(renamed: &DiffEntry, side: Side, other_path: Option<&String>) -> Conflict {
    let (ours_hash, ours_mode, theirs_hash, theirs_mode) = match side {
        Side::Ours => (renamed.new_hash, renamed.new_mode, None, None),
        Side::Theirs => (None, None, renamed.new_hash, renamed.new_mode),
    };
    Conflict {
        path: renamed.path.clone(),
        kind: ConflictKind::DeleteModify,
        base_hash: renamed.old_hash,
        ours_hash,
        theirs_hash,
        ours_mode,
        theirs_mode,
        rename: Some(RenameConflict {
            from: renamed.old_path.clone().unwrap_or_default(),
            other: other_path.cloned(),
        }),
    }
}

/// Whether a file of the tree at `root` stands where `path` needs a
/// directory.
fn blocked<S: ObjectSource + ?Sized>(
    store: &S,
    root: Option<Hash>,
    path: &str,
) -> Result<bool, StoreError> {
    let mut tree = root;
    let components: Vec<&str> = path.split('/').collect();
    let Some((_, dirs)) = components.split_last() else {
        return Ok(false);
    };
    for dir in dirs {
        let entries = load_entries(store, tree)?;
        match entries.iter().find(|e| e.name == dir.as_bytes()) {
            None => return Ok(false),
            Some(e) if e.mode == EntryMode::Tree => tree = Some(e.object_hash),
            Some(_) => return Ok(true),
        }
    }
    Ok(false)
}

/// Apply `edits` to the tree at `root` and write the result. With no edits
/// the root stays as it is.
fn edit_root<S: ObjectSource + ObjectSink + ?Sized>(
    store: &S,
    root: Option<Hash>,
    edits: &[Edit],
) -> Result<Option<Hash>, StoreError> {
    if edits.is_empty() {
        return Ok(root);
    }
    let edits: Vec<SplitEdit<'_>> = edits
        .iter()
        .map(|(path, entry)| (path.split('/').collect(), *entry))
        .collect();
    let entries = edit_tree(store, root, &edits, 0)?;
    Ok(Some(put_tree(store, entries)?))
}

/// The entries of the tree at `root` with `edits` applied. Each edit names
/// its path as components. A directory that the edits leave empty goes.
fn edit_tree<S: ObjectSource + ObjectSink + ?Sized>(
    store: &S,
    root: Option<Hash>,
    edits: &[SplitEdit<'_>],
    depth: usize,
) -> Result<Vec<TreeEntry>, StoreError> {
    if depth > MAX_TREE_DEPTH {
        return Err(StoreError::TreeTooDeep);
    }
    let mut entries: BTreeMap<Vec<u8>, TreeEntry> = load_entries(store, root)?
        .into_iter()
        .map(|e| (e.name.clone(), e))
        .collect();
    // Removals first, so a path that one edit removes and another sets
    // ends set.
    let mut leaves: Vec<(&str, Leaf)> = Vec::new();
    let mut below: BTreeMap<&str, Vec<SplitEdit<'_>>> = BTreeMap::new();
    for (components, entry) in edits {
        match components.split_first() {
            Some((name, [])) => leaves.push((name, *entry)),
            Some((dir, rest)) => below.entry(dir).or_default().push((rest.to_vec(), *entry)),
            None => {}
        }
    }
    leaves.sort_by_key(|(_, entry)| entry.is_some());
    for (name, entry) in leaves {
        match entry {
            Some((mode, object_hash)) => {
                entries.insert(
                    name.as_bytes().to_vec(),
                    TreeEntry {
                        name: name.as_bytes().to_vec(),
                        mode,
                        object_hash,
                    },
                );
            }
            None => {
                entries.remove(name.as_bytes());
            }
        }
    }
    for (dir, sub_edits) in below {
        let key = dir.as_bytes().to_vec();
        let sub_root = entries
            .get(&key)
            .filter(|e| e.mode == EntryMode::Tree)
            .map(|e| e.object_hash);
        let sub = edit_tree(store, sub_root, &sub_edits, depth + 1)?;
        if sub.is_empty() {
            entries.remove(&key);
        } else {
            let object_hash = put_tree(store, sub)?;
            entries.insert(
                key.clone(),
                TreeEntry {
                    name: key,
                    mode: EntryMode::Tree,
                    object_hash,
                },
            );
        }
    }
    Ok(entries.into_values().collect())
}
