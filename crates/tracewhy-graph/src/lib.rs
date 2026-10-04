//! The cause graph: typed nodes (processes, resources, observations, facts,
//! hypotheses, causes) linked by typed edges, every one carrying references to
//! the evidence that justifies it.
//!
//! The graph is append-only and indexed for O(1) node lookup by key, so
//! building it stays linear in the size of the trace.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use tracewhy_core::EvidenceRef;

pub type NodeId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Command,
    Process,
    File,
    Executable,
    Socket,
    Port,
    Host,
    Container,
    Service,
    Runtime,
    EnvironmentFact,
    Failure,
    Observation,
    Fact,
    Hypothesis,
    Cause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Spawned,
    Attempted,
    Opened,
    ResolvedTo,
    ConnectedTo,
    FailedWith,
    Caused,
    AssociatedWith,
    DefinedBy,
    UnavailableBecause,
    DependsOn,
    Corroborates,
    Contradicts,
    Explains,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    pub key: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CauseGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Set when the node limit was reached and nodes were dropped.
    #[serde(default)]
    pub truncated: bool,
    #[serde(skip)]
    index: HashMap<String, NodeId>,
    #[serde(skip)]
    outgoing: HashMap<NodeId, Vec<usize>>,
    #[serde(skip)]
    max_nodes: Option<usize>,
}

impl CauseGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limit(max_nodes: usize) -> Self {
        CauseGraph {
            max_nodes: Some(max_nodes),
            ..Self::default()
        }
    }

    /// Rebuild lookup indexes (needed after deserialization).
    pub fn reindex(&mut self) {
        self.index = self.nodes.iter().map(|n| (n.key.clone(), n.id)).collect();
        self.outgoing.clear();
        for (i, e) in self.edges.iter().enumerate() {
            self.outgoing.entry(e.from).or_default().push(i);
        }
    }

    /// Insert a node, or return the existing node with the same key (merging evidence).
    pub fn node(
        &mut self,
        kind: NodeKind,
        key: impl Into<String>,
        label: impl Into<String>,
        evidence: Vec<EvidenceRef>,
    ) -> Option<NodeId> {
        let key = key.into();
        if let Some(&id) = self.index.get(&key) {
            if let Some(n) = self.nodes.get_mut(id as usize) {
                for e in evidence {
                    if !n.evidence.contains(&e) {
                        n.evidence.push(e);
                    }
                }
            }
            return Some(id);
        }
        if let Some(max) = self.max_nodes {
            if self.nodes.len() >= max {
                self.truncated = true;
                return None;
            }
        }
        let id = self.nodes.len() as NodeId;
        self.nodes.push(Node {
            id,
            kind,
            key: key.clone(),
            label: label.into(),
            evidence,
        });
        self.index.insert(key, id);
        Some(id)
    }

    pub fn edge(&mut self, from: NodeId, to: NodeId, kind: EdgeKind, evidence: Vec<EvidenceRef>) {
        if let Some(list) = self.outgoing.get(&from) {
            for &i in list {
                if let Some(e) = self.edges.get_mut(i) {
                    if e.to == to && e.kind == kind {
                        for ev in evidence {
                            if !e.evidence.contains(&ev) {
                                e.evidence.push(ev);
                            }
                        }
                        return;
                    }
                }
            }
        }
        self.outgoing
            .entry(from)
            .or_default()
            .push(self.edges.len());
        self.edges.push(Edge {
            from,
            to,
            kind,
            evidence,
        });
    }

    pub fn find(&self, key: &str) -> Option<&Node> {
        self.index
            .get(key)
            .and_then(|&id| self.nodes.get(id as usize))
    }

    pub fn get(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id as usize)
    }

    pub fn outgoing(&self, id: NodeId) -> impl Iterator<Item = &Edge> {
        self.outgoing
            .get(&id)
            .into_iter()
            .flat_map(|v| v.iter())
            .filter_map(|&i| self.edges.get(i))
    }

    /// Shortest path (breadth-first) from `from` to `to` following edges of the
    /// given kinds. Returns the node ids on the path, inclusive.
    pub fn path(&self, from: NodeId, to: NodeId, kinds: &[EdgeKind]) -> Option<Vec<NodeId>> {
        let mut prev: HashMap<NodeId, NodeId> = HashMap::new();
        let mut queue = VecDeque::from([from]);
        let mut seen = std::collections::HashSet::from([from]);
        while let Some(cur) = queue.pop_front() {
            if cur == to {
                let mut path = vec![to];
                let mut c = to;
                while let Some(&p) = prev.get(&c) {
                    path.push(p);
                    c = p;
                }
                path.reverse();
                return Some(path);
            }
            for e in self.outgoing(cur) {
                if kinds.contains(&e.kind) && seen.insert(e.to) {
                    prev.insert(e.to, cur);
                    queue.push_back(e.to);
                }
            }
        }
        None
    }

    /// All evidence attached to a node and its incoming edges.
    pub fn evidence_for(&self, id: NodeId) -> Vec<EvidenceRef> {
        let mut out: Vec<EvidenceRef> =
            self.get(id).map(|n| n.evidence.clone()).unwrap_or_default();
        for e in self.edges.iter().filter(|e| e.to == id) {
            for ev in &e.evidence {
                if !out.contains(ev) {
                    out.push(ev.clone());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests;
