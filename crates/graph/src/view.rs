//! Views cut out of the graph for drawing or answering: a bounded set of nodes, the edges among
//! them, and how much was left out.

use crate::edge::{EdgeKind, Evidence};
use crate::node::{Node, NodeKey, NodeKind};
use serde::Serialize;

/// What a view may hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// Steps from the centre (ego views).
    pub depth: u32,
    /// Most nodes in the view.
    pub limit: usize,
    /// Kinds to show besides the centre; empty shows every kind.
    pub kinds: Vec<NodeKind>,
}

impl Default for Scope {
    fn default() -> Self {
        Self { depth: 2, limit: 80, kinds: Vec::new() }
    }
}

impl Scope {
    pub const MAX_LIMIT: usize = 400;
    pub const MAX_DEPTH: u32 = 4;

    pub fn new(depth: u32, limit: usize) -> Self {
        Self { depth: depth.clamp(1, Self::MAX_DEPTH), limit: limit.clamp(1, Self::MAX_LIMIT), kinds: Vec::new() }
    }

    pub fn kinds(mut self, kinds: Vec<NodeKind>) -> Self {
        self.kinds = kinds;
        self
    }

    pub fn allows(&self, kind: NodeKind) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&kind)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ViewNode {
    pub node: Node,
    /// Steps from the centre (0 for the centre; overview: 0 for the core, 1 for the rest).
    pub depth: u32,
    /// Neighbours in the graph this view does not show.
    pub more: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ViewEdge {
    /// Indices into the view's nodes.
    pub from: usize,
    pub to: usize,
    pub kind: EdgeKind,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct GraphView {
    /// Index of the centre node (ego views).
    pub centre: Option<usize>,
    pub nodes: Vec<ViewNode>,
    pub edges: Vec<ViewEdge>,
    /// Nodes next to the shown ones that did not fit.
    pub left_out: usize,
}

impl GraphView {
    pub fn index_of(&self, key: &NodeKey) -> Option<usize> {
        self.nodes.iter().position(|n| n.node.key() == key)
    }

    /// View indices linked to node `i`.
    pub fn neighbours(&self, i: usize) -> Vec<usize> {
        let mut out: Vec<usize> = self.edges.iter().filter_map(|e| if e.from == i { Some(e.to) } else if e.to == i { Some(e.from) } else { None }).collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// One link of a node as its detail lists it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Link {
    pub other: Node,
    pub kind: EdgeKind,
    /// The node is the edge's `from` end.
    pub outgoing: bool,
    pub count: u64,
    pub evidence: Vec<Evidence>,
}

impl Link {
    /// `has an account`, `derived from`... read from the node towards `other`.
    pub fn phrase(&self) -> &'static str {
        if self.outgoing { self.kind.label() } else { self.kind.reverse_label() }
    }
}

/// A node with every link and its evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NodeDetail {
    pub node: Node,
    /// Strongest and most valuable first.
    pub links: Vec<Link>,
    /// Links not listed (hubs have thousands).
    pub more_links: usize,
}
