//! Use cases of the connection map: the case's entity graph, built from capped case queries and
//! cached until the case changes, and the views and details cut out of it. Read-only. The first
//! build on a large case takes seconds; callers run it off the UI thread.

use crate::workbench::Workbench;
use parking_lot::Mutex;
use std::sync::Arc;
use strata_graph::{Graph, GraphBuilder, GraphView, Limits, Node, NodeDetail, NodeKey, ViewScope};
use strata_kernel::Result;

/// The last built graph and the case stamp it was built at.
#[derive(Default)]
pub(crate) struct GraphCache {
    built: Mutex<Option<(String, Arc<Graph>)>>,
    /// Held while building, so concurrent callers wait for one build instead of starting more.
    building: Mutex<()>,
}

impl GraphCache {
    fn current(&self, stamp: &str) -> Option<Arc<Graph>> {
        self.built.lock().as_ref().filter(|(s, _)| s == stamp).map(|(_, g)| g.clone())
    }
}

impl Workbench {
    /// The connection graph of the case: built on first use and again whenever findings,
    /// accounts, leads, mail, chain data or disks changed.
    pub fn connections(&self) -> Result<Arc<Graph>> {
        let stamp = self.case.connection_stamp()?;
        if let Some(graph) = self.connections.current(&stamp) {
            return Ok(graph);
        }
        let _one_build = self.connections.building.lock();
        if let Some(graph) = self.connections.current(&stamp) {
            return Ok(graph);
        }
        let facts = self.case.connection_facts(&Limits { min_confidence: Self::NOISE_FLOOR, ..Limits::default() })?;
        let graph = Arc::new(GraphBuilder::build(&facts));
        *self.connections.built.lock() = Some((stamp, graph.clone()));
        Ok(graph)
    }

    /// The ego network of an entity, given as a node key or as text a search resolves (an
    /// address, e-mail, login, key, file name...). `None` when nothing matches.
    pub fn connections_around(&self, entity: &str, scope: &ViewScope) -> Result<Option<GraphView>> {
        let graph = self.connections()?;
        Ok(graph.resolve(entity).and_then(|n| graph.around(n.key(), scope)))
    }

    /// Ego network of the likely owner (or the most valuable entity when no owner shows).
    pub fn connections_default(&self, scope: &ViewScope) -> Result<Option<GraphView>> {
        let graph = self.connections()?;
        Ok(graph.default_centre().and_then(|n| graph.around(n.key(), scope)))
    }

    /// The best-ranked entities of the whole case and what connects them.
    pub fn connections_overview(&self, scope: &ViewScope) -> Result<GraphView> {
        Ok(self.connections()?.overview(scope))
    }

    /// One entity with every link and the evidence for each.
    pub fn connection_detail(&self, entity: &str) -> Result<Option<NodeDetail>> {
        let graph = self.connections()?;
        Ok(graph.resolve(entity).and_then(|n| graph.detail(n.key())))
    }

    /// Entities matching a search, most valuable first.
    pub fn find_connections(&self, text: &str, limit: usize) -> Result<Vec<Node>> {
        Ok(self.connections()?.find(text, limit).into_iter().cloned().collect())
    }

    /// The node a stored finding became (falls back to its value when the finding itself was
    /// not part of the graph, e.g. another copy of the same key).
    pub fn connection_of_finding(&self, hit: i64, value: &str) -> Result<Option<NodeKey>> {
        let graph = self.connections()?;
        Ok(graph.node_of_hit(hit).or_else(|| graph.resolve(value)).map(|n| n.key().clone()))
    }
}
