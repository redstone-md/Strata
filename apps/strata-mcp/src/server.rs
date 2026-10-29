//! The server object: one idle workbench over the case plus the tool router. Tools run their
//! blocking case queries through [`StrataServer::query`].

use crate::format::{Reply, fail};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ServerHandler, ServiceExt, tool_handler};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;
use strata_workbench::Workbench;

const INSTRUCTIONS: &str = "Strata is a disk-forensics workbench used to find lost cryptocurrency wallets on old disks. \
This server gives read-only access to one Strata case: findings (keys, seeds, wallets, addresses, identities), \
on-chain balances, the timeline, accounts, ranked leads, file listings, stored searches, recovered e-mail \
messages (list_mail, get_mail: live, deleted and carved from free space), the connection map (connections: \nwho the owner is and how identities, accounts, keys, files and addresses link to services and money), the computers \neach disk held and when they were in use (machines, usage_periods) and job progress. \nStart with case_overview. Findings are grouped by value like in the app and hide noise below confidence 0.2 \
unless you lower min_confidence. Disks are referred to by numeric id. Times are UTC, written as YYYY-MM-DD HH:MM:SS. \
Lists are paged: pass offset=next_offset to continue. Secrets are shown in clear on purpose; nothing here can \
start analysis or change the case.";

/// MCP server over one open case.
#[derive(Clone)]
pub struct StrataServer {
    wb: Arc<Workbench>,
    tool_router: ToolRouter<Self>,
}

impl StrataServer {
    /// Open an existing case without resuming, queueing or re-checking anything. A folder
    /// without a case database is refused rather than created.
    pub fn open(case_dir: &Path) -> Reply<Self> {
        if !case_dir.join("case.db").is_file() {
            return Err(format!("{} is not a Strata case (no case.db)", case_dir.display()));
        }
        Ok(Self::new(Workbench::open_idle(case_dir).map_err(fail)?))
    }

    /// Serve an already open workbench (the caller is responsible for opening it idle).
    pub fn new(wb: Arc<Workbench>) -> Self {
        Self { wb, tool_router: crate::tools::router() }
    }

    /// Answer MCP requests on stdin/stdout until the client disconnects.
    pub async fn serve_stdio(self) -> Result<(), Box<dyn std::error::Error>> {
        let service = self.serve(rmcp::transport::stdio()).await?;
        service.waiting().await?;
        Ok(())
    }

    /// Run a blocking case query off the async runtime and render its result as compact JSON.
    pub(crate) async fn query<T, F>(&self, f: F) -> Reply<String>
    where
        T: Serialize + Send + 'static,
        F: FnOnce(&Workbench) -> Reply<T> + Send + 'static,
    {
        let wb = self.wb.clone();
        let value = tokio::task::spawn_blocking(move || f(&wb)).await.map_err(|e| format!("query stopped: {e}"))??;
        serde_json::to_string(&value).map_err(fail)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for StrataServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("strata", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}
