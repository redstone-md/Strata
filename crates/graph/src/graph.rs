//! The built graph and the questions asked of it: what is around an entity, what matters most
//! overall, what one node is linked to and why, and which node a search means.

use crate::edge::Edge;
use crate::node::{Node, NodeKey, NodeKind};
use crate::view::{GraphView, Link, NodeDetail, ViewScope, ViewEdge, ViewNode};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

/// Neighbours taken per node beyond the first ring of an ego view.
const FANOUT: usize = 12;
/// Links listed in a node's detail.
const MAX_LINKS: usize = 200;

pub struct Graph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    /// Edge indices per node.
    adjacency: Vec<Vec<usize>>,
    index: HashMap<NodeKey, usize>,
    by_hit: HashMap<i64, usize>,
}

/// Higher first, ties by key so every ordering is deterministic.
fn by_rank(a: (f32, &NodeKey), b: (f32, &NodeKey)) -> Ordering {
    b.0.total_cmp(&a.0).then_with(|| a.1.cmp(b.1))
}

impl Graph {
    pub(crate) fn new(nodes: Vec<Node>, edges: Vec<Edge>, by_hit: HashMap<i64, usize>) -> Self {
        let mut adjacency = vec![Vec::new(); nodes.len()];
        for (i, e) in edges.iter().enumerate() {
            adjacency[e.from].push(i);
            adjacency[e.to].push(i);
        }
        let index = nodes.iter().enumerate().map(|(i, n)| (n.key.clone(), i)).collect();
        Self { nodes, edges, adjacency, index, by_hit }
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    pub fn node(&self, key: &NodeKey) -> Option<&Node> {
        self.index.get(key).map(|i| &self.nodes[*i])
    }

    /// The node a stored finding became.
    pub fn node_of_hit(&self, hit: i64) -> Option<&Node> {
        self.by_hit.get(&hit).map(|i| &self.nodes[*i])
    }

    /// Nodes per kind.
    pub fn counts(&self) -> Vec<(NodeKind, usize)> {
        NodeKind::ALL.iter().map(|k| (*k, self.nodes.iter().filter(|n| n.kind == *k).count())).filter(|(_, n)| *n > 0).collect()
    }

    /// Where a view opens: the likely owner, else the most valuable entity.
    pub fn default_centre(&self) -> Option<&Node> {
        self.nodes
            .iter()
            .find(|n| n.flags.owner)
            .or_else(|| self.nodes.iter().filter(|n| !n.kind.is_hub()).min_by(|a, b| by_rank((a.score, &a.key), (b.score, &b.key))))
    }

    /// Nodes matching a search: a node key, an exact value (any case), then values containing
    /// the text; most valuable first.
    pub fn find(&self, text: &str, limit: usize) -> Vec<&Node> {
        let text = text.trim();
        if text.is_empty() {
            return Vec::new();
        }
        if let Some(n) = NodeKey::parse(text).and_then(|k| self.node(&k)) {
            return vec![n];
        }
        let needle = text.to_lowercase();
        let mut exact: Vec<&Node> = self.nodes.iter().filter(|n| n.label.to_lowercase() == needle || n.key.as_str().ends_with(&format!(":{text}"))).collect();
        let mut partial: Vec<&Node> = self.nodes.iter().filter(|n| !exact.contains(n) && n.label.to_lowercase().contains(&needle)).collect();
        let order = |a: &&Node, b: &&Node| by_rank((a.score, &a.key), (b.score, &b.key));
        exact.sort_by(order);
        partial.sort_by(order);
        exact.into_iter().chain(partial).take(limit).collect()
    }

    /// The node a search means: the best of [`Self::find`].
    pub fn resolve(&self, text: &str) -> Option<&Node> {
        self.find(text, 1).into_iter().next()
    }

    /// Neighbours of `i` as `(node, weight)`, strongest and most valuable first.
    fn ranked_neighbours(&self, i: usize) -> Vec<(usize, f32)> {
        let mut best: HashMap<usize, f32> = HashMap::new();
        for e in &self.adjacency[i] {
            let edge = &self.edges[*e];
            let j = edge.other(i);
            let w = edge.weight() * (self.nodes[j].score + 5.0);
            let slot = best.entry(j).or_insert(0.0);
            *slot = slot.max(w);
        }
        let mut out: Vec<(usize, f32)> = best.into_iter().collect();
        out.sort_by(|a, b| by_rank((a.1, &self.nodes[a.0].key), (b.1, &self.nodes[b.0].key)));
        out
    }

    /// The ego network of `key`: rings of neighbours out to `scope.depth`, strongest first, at
    /// most `scope.limit` nodes. Hubs (disks, services) are shown but not walked through
    /// unless they are the centre.
    pub fn around(&self, key: &NodeKey, scope: &ViewScope) -> Option<GraphView> {
        let centre = *self.index.get(key)?;
        let mut depth_of: HashMap<usize, u32> = HashMap::from([(centre, 0)]);
        let mut order = vec![centre];
        let mut frontier = vec![centre];
        for depth in 1..=scope.depth {
            let mut candidates: Vec<(usize, f32)> = Vec::new();
            for &n in &frontier {
                if n != centre && self.nodes[n].kind.is_hub() {
                    continue;
                }
                let fanout = if n == centre { scope.limit } else { FANOUT };
                candidates.extend(
                    self.ranked_neighbours(n)
                        .into_iter()
                        .filter(|(j, _)| !depth_of.contains_key(j) && scope.allows(self.nodes[*j].kind))
                        .take(fanout),
                );
            }
            candidates.sort_by(|a, b| by_rank((a.1, &self.nodes[a.0].key), (b.1, &self.nodes[b.0].key)));
            frontier.clear();
            for (j, _) in candidates {
                if order.len() >= scope.limit {
                    break;
                }
                if let std::collections::hash_map::Entry::Vacant(slot) = depth_of.entry(j) {
                    slot.insert(depth);
                    order.push(j);
                    frontier.push(j);
                }
            }
        }
        let mut view = self.view(&order, |i| depth_of.get(&i).copied().unwrap_or(0), scope);
        view.centre = Some(0);
        Some(view)
    }

    /// The most important part of the whole case: the best-ranked entities, what connects
    /// them, and the disks and services they hang off.
    pub fn overview(&self, scope: &ViewScope) -> GraphView {
        let mut ranked: Vec<usize> = (0..self.nodes.len()).filter(|i| !self.nodes[*i].kind.is_hub() && scope.allows(self.nodes[*i].kind)).collect();
        ranked.sort_by(|a, b| by_rank((self.nodes[*a].score, &self.nodes[*a].key), (self.nodes[*b].score, &self.nodes[*b].key)));
        let core_len = (scope.limit * 11 / 20).max(1);
        let mut picked: Vec<usize> = ranked.iter().copied().take(core_len).collect();
        let mut set: BTreeSet<usize> = picked.iter().copied().collect();
        let add = |picked: &mut Vec<usize>, set: &mut BTreeSet<usize>, budget: usize, mut pool: Vec<(usize, f32)>| {
            pool.sort_by(|a, b| by_rank((a.1, &self.nodes[a.0].key), (b.1, &self.nodes[b.0].key)));
            for (j, _) in pool {
                if picked.len() >= budget {
                    break;
                }
                if set.insert(j) {
                    picked.push(j);
                }
            }
        };
        // Connectors: nodes joining two or more of the core.
        let mut links: HashMap<usize, (usize, f32)> = HashMap::new();
        for &i in &picked {
            for (j, w) in self.ranked_neighbours(i) {
                if !set.contains(&j) && !self.nodes[j].kind.is_hub() && scope.allows(self.nodes[j].kind) {
                    let slot = links.entry(j).or_insert((0, 0.0));
                    *slot = (slot.0 + 1, slot.1.max(w));
                }
            }
        }
        let connectors = links.iter().filter(|(_, (n, _))| *n >= 2).map(|(j, (n, w))| (*j, *n as f32 * 1000.0 + w)).collect();
        add(&mut picked, &mut set, scope.limit * 4 / 5, connectors);
        let strongest = links.iter().map(|(j, (_, w))| (*j, *w)).collect();
        add(&mut picked, &mut set, scope.limit * 9 / 10, strongest);
        let mut hubs: HashMap<usize, usize> = HashMap::new();
        for &i in &picked {
            for e in &self.adjacency[i] {
                let j = self.edges[*e].other(i);
                if self.nodes[j].kind.is_hub() && scope.allows(self.nodes[j].kind) {
                    *hubs.entry(j).or_default() += 1;
                }
            }
        }
        add(&mut picked, &mut set, scope.limit, hubs.into_iter().map(|(j, n)| (j, n as f32)).collect());
        let core: BTreeSet<usize> = picked.iter().take(core_len).copied().collect();
        self.view(&picked, |i| if core.contains(&i) { 0 } else { 1 }, scope)
    }

    fn view(&self, order: &[usize], depth: impl Fn(usize) -> u32, scope: &ViewScope) -> GraphView {
        let position: HashMap<usize, usize> = order.iter().enumerate().map(|(v, g)| (*g, v)).collect();
        let mut edges = Vec::new();
        let mut shown: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); order.len()];
        let mut left_out = BTreeSet::new();
        for (v, &g) in order.iter().enumerate() {
            for e in &self.adjacency[g] {
                let edge = &self.edges[*e];
                let other = edge.other(g);
                match position.get(&other) {
                    Some(&w) => {
                        shown[v].insert(w);
                        if edge.from == g {
                            edges.push(ViewEdge { from: v, to: w, kind: edge.kind, count: edge.count });
                        }
                    }
                    None if scope.allows(self.nodes[other].kind) && !self.nodes[g].kind.is_hub() => {
                        left_out.insert(other);
                    }
                    None => {}
                }
            }
        }
        let nodes = order
            .iter()
            .enumerate()
            .map(|(v, &g)| {
                let degree: BTreeSet<usize> =
                    self.adjacency[g].iter().map(|e| self.edges[*e].other(g)).filter(|o| scope.allows(self.nodes[*o].kind)).collect();
                ViewNode { node: self.nodes[g].clone(), depth: depth(g), more: degree.len().saturating_sub(shown[v].len()) }
            })
            .collect();
        GraphView { centre: None, nodes, edges, left_out: left_out.len() }
    }

    /// One node with every link (strongest and most valuable first) and its evidence.
    pub fn detail(&self, key: &NodeKey) -> Option<NodeDetail> {
        let i = *self.index.get(key)?;
        let mut links: Vec<(f32, Link)> = self.adjacency[i]
            .iter()
            .map(|e| {
                let edge = &self.edges[*e];
                let other = &self.nodes[edge.other(i)];
                let link = Link { other: other.clone(), kind: edge.kind, outgoing: edge.from == i, count: edge.count, evidence: edge.evidence.clone() };
                (edge.weight() * (other.score + 5.0), link)
            })
            .collect();
        links.sort_by(|a, b| by_rank((a.0, &a.1.other.key), (b.0, &b.1.other.key)));
        let more_links = links.len().saturating_sub(MAX_LINKS);
        Some(NodeDetail { node: self.nodes[i].clone(), links: links.into_iter().take(MAX_LINKS).map(|(_, l)| l).collect(), more_links })
    }
}
