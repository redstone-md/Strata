//! `strata-mcp --case <CASE_DIR>`: serve one Strata case to an MCP client over stdio.
//! Stdout carries the protocol; everything human-readable goes to stderr.

use clap::Parser;
use std::path::PathBuf;
use strata_mcp::StrataServer;

#[derive(Parser)]
#[command(name = "strata-mcp", version, about = "Read-only MCP server for one Strata case (stdio)")]
struct Args {
    /// Existing case folder, e.g. D:\cases\laptop.strata
    #[arg(short, long)]
    case: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("strata-mcp: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let server = StrataServer::open(&args.case)?;
    eprintln!("strata-mcp: serving case {} (read-only)", args.case.display());
    server.serve_stdio().await
}
