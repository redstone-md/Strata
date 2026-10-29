//! Connections context: the entity graph of a case. Who the owner is, which accounts, keys,
//! wallets, files and addresses belong to them, how they link to services and money, and the
//! concrete evidence for every link.
//!
//! The case store hands over capped, aggregated [`Facts`]; [`GraphBuilder`] turns them into a
//! [`Graph`] of typed [`Node`]s and evidenced [`Edge`]s, leaves out noise (identities only seen
//! in system files or in hundreds of files with no sign of use) and ranks every node by its
//! closeness to money and ownership. Views are cut out of the graph — [`Graph::around`] (an ego
//! network) and [`Graph::overview`] — and [`Layout`] places a view deterministically.

mod builder;
mod edge;
mod facts;
mod graph;
mod layout;
mod node;
mod paths;
mod rank;
mod view;

pub use builder::GraphBuilder;
pub use edge::{Edge, EdgeKind, Evidence};
pub use facts::{ChainFact, DiskFact, Facts, FindingFact, Limits, MailFact, MentionFact, SpreadFact, TxFact};
pub use graph::Graph;
pub use layout::Layout;
pub use node::{ChainState, Flags, Node, NodeKey, NodeKind};
pub use paths::{PathClass, classify as classify_path, file_name};
pub use view::{GraphView, Link, NodeDetail, ViewScope, ViewEdge, ViewNode};

#[cfg(test)]
mod tests;
