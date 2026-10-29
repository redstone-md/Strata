//! MCP server over one Strata case, for AI assistants helping with an investigation.
//!
//! Read-only by design: the case is opened idle (no job is resumed, queued or re-checked) and
//! every tool is a workbench query. Tools live in [`tools`], one module per area of the case;
//! [`tools::router`] lists them all.

mod format;
mod server;
pub mod tools;

pub use server::StrataServer;
