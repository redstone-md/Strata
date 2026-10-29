//! Use cases of the connection map: the case's entity graph, built from capped case queries and
//! cached until the case changes, and the views and details cut out of it. Read-only. The first
//! build on a large case takes seconds; callers run it off the UI thread.

use crate::workbench::Workbench;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strata_graph::{Graph, GraphBuilder, GraphView, Limits, Node, NodeDetail, NodeKey, ViewScope};
use strata_kernel::Result;

/// While jobs keep adding findings the stamp changes constantly; a graph this young is used
/// anyway instead of being rebuilt on every click. The app rebuilds when a job ends.
const FRESH_ENOUGH: Duration = Duration::from_secs(120);

/// The last built graph, the case stamp it was built at and when.
#[derive(Default)]
pub(crate) struct GraphCache {
    built: Mutex<Option<(String, Instant, Arc<Graph>)>>,
    /// Held while building, so concurrent callers wait for one build instead of starting more.
    building: Mutex<()>,
    /// What the build in progress is reading, and since when.
    step: Mutex<Option<(&'static str, Instant)>>,
}

impl GraphCache {
    fn current(&self, stamp: &str) -> Option<Arc<Graph>> {
        self.built.lock().as_ref().filter(|(s, at, _)| s == stamp || at.elapsed() < FRESH_ENOUGH).map(|(_, _, g)| g.clone())
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
        let started = Instant::now();
        let step = |what: &'static str| *self.connections.step.lock() = Some((what, started));
        let limits = Limits { min_confidence: Self::NOISE_FLOOR, ..Limits::default() };
        let built = self.case.connection_facts(&limits, &step).map(|facts| {
            step("Linking entities");
            Arc::new(GraphBuilder::build(&facts))
        });
        *self.connections.step.lock() = None;
        let graph = built?;
        *self.connections.built.lock() = Some((stamp, Instant::now(), graph.clone()));
        Ok(graph)
    }

    /// What a connection-map build in progress is doing and for how long, if one runs.
    pub fn connections_step(&self) -> Option<(&'static str, Duration)> {
        self.connections.step.lock().map(|(what, since)| (what, since.elapsed()))
    }

    /// Forget the built graph so the next request rebuilds it (a job ended, the user asked).
    pub fn refresh_connections(&self) {
        *self.connections.built.lock() = None;
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
