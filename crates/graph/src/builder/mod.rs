//! Builds the [`Graph`] from [`Facts`]: ownership signals and noise first, then nodes and
//! evidenced edges per source (findings, chain, accounts, mail, leads), then ranking.

mod findings;
mod ownership;
mod people;

use crate::edge::{Edge, EdgeKind, Evidence};
use crate::facts::Facts;
use crate::graph::Graph;
use crate::node::{Node, NodeKey, NodeKind};
use crate::rank;
use ownership::Signals;
use std::collections::HashMap;

/// Nodes and edges while they are being collected.
#[derive(Default)]
pub(crate) struct Draft {
    nodes: Vec<Node>,
    index: HashMap<NodeKey, usize>,
    edges: Vec<Edge>,
    edge_index: HashMap<(usize, usize, EdgeKind), usize>,
    /// Stored finding id → the node it became.
    by_hit: HashMap<i64, usize>,
}

impl Draft {
    pub fn get(&self, key: &NodeKey) -> Option<usize> {
        self.index.get(key).copied()
    }

    /// The node under `key`, made by `make` the first time.
    pub fn node(&mut self, key: NodeKey, make: impl FnOnce(NodeKey) -> Node) -> usize {
        if let Some(i) = self.index.get(&key) {
            return *i;
        }
        let i = self.nodes.len();
        self.index.insert(key.clone(), i);
        self.nodes.push(make(key));
        i
    }

    pub fn at(&mut self, i: usize) -> &mut Node {
        &mut self.nodes[i]
    }

    /// Add one piece of evidence to the `kind` link between two nodes (made on first use).
    /// Symmetric kinds are stored once per pair whichever end comes first.
    pub fn link(&mut self, from: usize, to: usize, kind: EdgeKind, evidence: Option<Evidence>) {
        if from == to {
            return;
        }
        let (a, b) = if kind.symmetric() { (from.min(to), from.max(to)) } else { (from, to) };
        let next = self.edges.len();
        let i = *self.edge_index.entry((a, b, kind)).or_insert(next);
        if i == next {
            self.edges.push(Edge::new(a, b, kind));
        }
        self.edges[i].add(evidence);
    }

    pub fn remember_hit(&mut self, hit: i64, node: usize) {
        self.by_hit.entry(hit).or_insert(node);
    }
}

/// Turns facts into a ranked graph.
pub struct GraphBuilder;

impl GraphBuilder {
    pub fn build(facts: &Facts) -> Graph {
        let signals = Signals::collect(facts);
        let mut draft = Draft::default();
        for disk in &facts.disks {
            draft.node(NodeKey::disk(disk.id), |k| {
                let mut n = Node::new(k, NodeKind::Disk, disk.label.clone(), "disk");
                n.on_disk(disk.id);
                n.score = 4.0;
                n
            });
        }
        findings::add(&mut draft, facts, &signals);
        people::add_accounts(&mut draft, facts, &signals);
        people::add_mail(&mut draft, facts, &signals);
        people::add_leads(&mut draft, facts);
        Self::rank(&mut draft, &signals);
        Graph::new(draft.nodes, draft.edges, draft.by_hit)
    }

    /// Identity scores from ownership, the likely owner, then propagation.
    fn rank(draft: &mut Draft, signals: &Signals) {
        let mut owner: Option<(f32, NodeKey, usize)> = None;
        for (i, node) in draft.nodes.iter_mut().enumerate() {
            if node.kind != NodeKind::Identity {
                continue;
            }
            let o = signals.of(&node.label);
            let (score, why) = o.score();
            node.score = score;
            for w in why {
                node.because(w);
            }
            let better = owner.as_ref().is_none_or(|(best, key, _)| score > *best || (score == *best && node.key < *key));
            if o.any() && better {
                owner = Some((score, node.key.clone(), i));
            }
        }
        if let Some((_, _, i)) = owner {
            let node = &mut draft.nodes[i];
            node.flags.owner = true;
            node.because("the most likely owner: the strongest signs of belonging to the user");
        }
        let mut adjacency = vec![Vec::new(); draft.nodes.len()];
        for (i, e) in draft.edges.iter().enumerate() {
            adjacency[e.from].push(i);
            adjacency[e.to].push(i);
        }
        rank::propagate(&mut draft.nodes, &draft.edges, &adjacency);
    }
}
