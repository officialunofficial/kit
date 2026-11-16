//! A shared completeness scan for hard and soft retention roots. Each object
//! is read once. Missing-closure results propagate to every dependent root;
//! only complete roots contribute to the final mark. Other errors fail closed.

use super::{ChunkIds, GcRootsError, LiveSet, MarkLimits, SoftRoot};
use crate::hash::{self, Hash};
use crate::object::ObjectType;
use crate::ops::graph::{ClosureMode, children};
use crate::store::{ObjectStore, StoreError};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;

#[derive(Clone, Copy)]
enum Status {
    Visiting,
    Complete,
    Missing(Hash),
}

struct Node {
    edges: Vec<Hash>,
    chunks: bool,
    status: Status,
}

pub(super) struct SoftGraph<'a> {
    store: &'a ObjectStore,
    limits: MarkLimits,
    nodes: BTreeMap<Hash, Node>,
    chunks: BTreeMap<Hash, Option<ObjectType>>,
    object_edges: usize,
    chunk_edges: usize,
}

impl<'a> SoftGraph<'a> {
    pub(super) fn new(store: &'a ObjectStore, limits: MarkLimits) -> Self {
        Self {
            store,
            limits,
            nodes: BTreeMap::new(),
            chunks: BTreeMap::new(),
            object_edges: 0,
            chunk_edges: 0,
        }
    }

    fn load(&mut self, h: Hash) -> Result<Node, GcRootsError> {
        let kind = match self.chunks.get(&h).copied() {
            Some(Some(kind)) => Ok(kind),
            Some(None) => Err(StoreError::ObjectNotFound(hash::to_hex(&h))),
            None => self.store.object_type(&h),
        };
        let kind = match kind {
            Ok(kind) => kind,
            Err(StoreError::ObjectNotFound(_)) => {
                return Ok(Node {
                    edges: vec![],
                    chunks: false,
                    status: Status::Missing(h),
                });
            }
            Err(e) => return Err(e.into()),
        };
        if matches!(kind, ObjectType::Blob | ObjectType::Delta) {
            return Ok(Node {
                edges: vec![],
                chunks: false,
                status: Status::Complete,
            });
        }
        let object = self.store.read_object(&h)?;
        let edges = children(&object, ClosureMode::History);
        let chunks = kind == ObjectType::ChunkedBlob;
        let (used, cap) = if chunks {
            (&mut self.chunk_edges, self.limits.chunk_cap)
        } else {
            (&mut self.object_edges, self.limits.cap.saturating_mul(8))
        };
        *used = used.saturating_add(edges.len());
        if *used > cap {
            return Err(GcRootsError::Truncated);
        }
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
                    let kind = match self.store.object_type(chunk) {
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
            edges,
            chunks,
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
                self.nodes.get_mut(&h).expect("loaded node").status = status;
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

    fn live(&self, roots: &BTreeSet<Hash>) -> Result<LiveSet, GcRootsError> {
        let mut objects = BTreeSet::new();
        let mut ids = ChunkIds::new(self.limits.compact_floor, self.limits.chunk_cap);
        let mut queue = VecDeque::from_iter(roots.iter().copied());
        while let Some(h) = queue.pop_front() {
            if !objects.insert(h) {
                continue;
            }
            let node = &self.nodes[&h];
            if node.chunks {
                ids.extend(&node.edges)?;
            } else {
                queue.extend(&node.edges);
            }
        }
        ids.compact()?;
        ids.ids.retain(|h| !objects.contains(h));
        for chunk in &ids.ids {
            if self.chunks[chunk] != Some(ObjectType::Blob) {
                let manifest = objects
                    .iter()
                    .find(|h| {
                        let node = &self.nodes[*h];
                        node.chunks && node.edges.contains(chunk)
                    })
                    .copied()
                    .unwrap_or(hash::ZERO);
                return Err(GcRootsError::ChunkNotBlob {
                    manifest,
                    chunk: *chunk,
                });
            }
        }
        Ok(LiveSet {
            objects,
            chunks: ids.ids,
        })
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
    let live = graph.live(&roots)?;
    progress("gc_mark", live.len(), 0);
    Ok((live, skipped.into_iter().collect()))
}
