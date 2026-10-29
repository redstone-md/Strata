//! The tools, one module per area of the case. Each module holds its parameter and output
//! types and one `#[tool_router]` block on [`StrataServer`]; [`router`] joins them. A new
//! area (mail, say) is a new module plus one line in [`router`].

pub mod browser;
pub mod chain;
pub mod files;
pub mod findings;
pub mod graph;
pub mod insights;
pub mod machines;
pub mod mail;
pub mod overview;
pub mod searches;
pub mod timeline;

use crate::StrataServer;
use rmcp::handler::server::router::tool::ToolRouter;

/// Every tool the server offers.
pub(crate) fn router() -> ToolRouter<StrataServer> {
    StrataServer::overview_tools()
        + StrataServer::finding_tools()
        + StrataServer::chain_tools()
        + StrataServer::timeline_tools()
        + StrataServer::insight_tools()
        + StrataServer::file_tools()
        + StrataServer::search_tools()
        + StrataServer::mail_tools()
        + StrataServer::browser_tools()
        + StrataServer::graph_tools()
        + StrataServer::machine_tools()
}

/// Disk id parameter as the workbench's evidence id.
pub(crate) fn disk(id: Option<u32>) -> Option<strata_workbench::EvidenceId> {
    id.map(strata_workbench::EvidenceId::new)
}
