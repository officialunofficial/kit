//! A shared completeness scan for hard and soft retention roots. Each object
//! is read once during classification. Only statuses survive postorder; the
//! existing marker then walks the complete roots together. Missing-closure
//! results are shared across roots; other errors still fail closed.

use super::{GcRootsError, LiveSet, MarkLimits, SoftRoot, mark_live_observed};
use crate::hash::{self, Hash};
use crate::object::{Object, ObjectType};
use crate::ops::graph::{ClosureMode, children};
use crate::store::{ObjectStore, StoreError};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Clone, Copy)]
enum Status {
    Visiting,
    Complete,
    Missing(Hash),
}

struct Node {
    edges: Vec<Hash>,
    status: Status,
}

pub(super) struct SoftGraph<'a> {
    store: &'a ObjectStore,
    limits: MarkLimits,
    nodes: BTreeMap<Hash, Node>,
    chunks: BTreeMap<Hash, Option<ObjectType>>,
}

impl<'a> SoftGraph<'a> {
    pub(super) fn new(store: &'a ObjectStore, limits: MarkLimits) -> Self {
        Self {
            store,
            limits,
            nodes: BTreeMap::new(),
            chunks: BTreeMap::new(),
        }
    }

    fn load(&mut self, h: Hash) -> Result<Node, GcRootsError> {
        let kind = match self.chunks.get(&h).copied() {
            Some(Some(kind)) => Ok(kind),
            Some(None) => Err(StoreError::ObjectNotFound(hash::to_hex(&h))),
            None => self.store.gc_object_type(&h),
        };
        let kind = match kind {
            Ok(kind) => kind,
            Err(StoreError::ObjectNotFound(_)) => {
                return Ok(Node {
                    edges: vec![],
                    status: Status::Missing(h),
                });
            }
            Err(e) => return Err(e.into()),
        };
        if matches!(kind, ObjectType::Blob | ObjectType::Delta) {
            return Ok(Node {
                edges: vec![],
                status: Status::Complete,
            });
        }
        let object = self.store.read_object(&h)?;
        let edges = children(&object, ClosureMode::History);
        let chunks = matches!(object, Object::ChunkedBlob(_));
        let mut status = Status::Visiting;
        if chunks {
            status = Status::Complete;
            for chunk in &edges {
                let present = if let Some(kind) = self.chunks.get(chunk) {
                    kind.is_some()
                } else {
                    if self.chunks.len() >= self.limits.chunk_cap {
                        return Err(GcRootsError::TooManyChunks {
                            count: self.chunks.len() + 1,
                            cap: self.limits.chunk_cap,
                        });
                    }
                    let kind = match self.store.gc_chunk_type(chunk) {
                        Ok(kind) => Some(kind),
                        Err(StoreError::ObjectNotFound(_)) => None,
                        Err(e) => return Err(e.into()),
                    };
                    self.chunks.insert(*chunk, kind);
                    kind.is_some()
                };
                if !present {
                    status = Status::Missing(*chunk);
                }
            }
        }
        Ok(Node {
            edges: if chunks { vec![] } else { edges },
            status,
        })
    }

    /// Iterative postorder: no recursion on an untrusted history's depth.
    pub(super) fn classify(&mut self, root: Hash) -> Result<Option<Hash>, GcRootsError> {
        let mut stack = vec![(root, false)];
        while let Some((h, finish)) = stack.pop() {
            if finish {
                let node = &self.nodes[&h];
                let mut status = Status::Complete;
                for edge in &node.edges {
                    match self.nodes[edge].status {
                        Status::Complete => {}
                        Status::Missing(missing) => status = Status::Missing(missing),
                        Status::Visiting => return Err(GcRootsError::Truncated),
                    }
                }
                let node = self.nodes.get_mut(&h).expect("loaded node");
                node.status = status;
                // Completed nodes retain only their memoized verdict. Shared
                // tree entries and repeated chunk references add no new cap.
                node.edges = Vec::new();
                continue;
            }
            if let Some(node) = self.nodes.get(&h) {
                if matches!(node.status, Status::Visiting) {
                    return Err(GcRootsError::Truncated);
                }
                continue;
            }
            if self.nodes.len() >= self.limits.cap {
                return Err(GcRootsError::Truncated);
            }
            let node = self.load(h)?;
            if matches!(node.status, Status::Visiting) {
                stack.push((h, true));
                stack.extend(node.edges.iter().rev().map(|edge| (*edge, false)));
            }
            self.nodes.insert(h, node);
        }
        Ok(match self.nodes[&root].status {
            Status::Missing(missing) => Some(missing),
            Status::Complete => None,
            Status::Visiting => unreachable!("postorder completes its root"),
        })
    }

    #[cfg(test)]
    pub(super) fn scanned(&self) -> usize {
        self.nodes.len()
    }
}

pub(super) fn mark(
    store: &ObjectStore,
    hard: BTreeSet<Hash>,
    soft: Vec<SoftRoot>,
    limits: MarkLimits,
    progress: &mut dyn FnMut(&'static str, usize, u64),
) -> Result<(LiveSet, Vec<PathBuf>), GcRootsError> {
    let mut graph = SoftGraph::new(store, limits);
    let mut roots = hard;
    let mut last = std::time::Instant::now();
    progress("gc_mark", 0, 0);
    for root in &roots {
        if let Some(missing) = graph.classify(*root)? {
            return Err(StoreError::ObjectNotFound(hash::to_hex(&missing)).into());
        }
        if last.elapsed() >= std::time::Duration::from_millis(100) {
            progress("gc_mark", graph.nodes.len(), 0);
            last = std::time::Instant::now();
        }
    }
    let mut skipped = BTreeSet::new();
    for root in soft {
        if graph.classify(root.hash)?.is_some() {
            skipped.insert(root.state_file);
        } else {
            roots.insert(root.hash);
        }
        if last.elapsed() >= std::time::Duration::from_millis(100) {
            progress("gc_mark", graph.nodes.len(), 0);
            last = std::time::Instant::now();
        }
    }
    // Release completeness metadata before the ordinary, shared union mark.
    // That mark retains the existing distinct-object and distinct-chunk caps.
    drop(graph);
    let live = mark_live_observed(store, &roots, limits, progress)?;
    progress("gc_mark", live.len(), 0);
    Ok((live, skipped.into_iter().collect()))
}
