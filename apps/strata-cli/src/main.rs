//! Headless front-end for long unattended runs and scripting.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use strata_workbench::{EvidenceId, HitCategory, HitQuery, JobState, Workbench};

#[derive(Parser)]
#[command(name = "strata-cli", about = "Strata forensic workbench (headless)")]
struct Cli {
    /// Case folder (created if missing), e.g. D:\cases\samsung.strata
    #[arg(short, long)]
    case: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register a disk image (.img/.dd/.001/.rdr) or \\.\PhysicalDriveN.
    Add { location: String },
    /// List evidence and volumes.
    List,
    /// Index files and run the single-pass scan (resumes an interrupted scan).
    Analyse {
        /// Evidence id; all evidence when omitted.
        id: Option<u32>,
    },
    /// Print stored findings.
    Hits {
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        text: Option<String>,
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f32,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Findings shared between disks and files that differ across disks.
    Correlate,
    /// Show looked-up address balances; `--endpoint` changes the Esplora server.
    Balances {
        #[arg(long)]
        endpoint: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let wb = Workbench::open(&cli.case)?;
    match cli.command {
        Command::Add { location } => {
            let r = wb.add_evidence(&location)?;
            println!("added {} {} ({} bytes, {} volumes)", r.id, r.info.label, r.info.len, r.volumes.len());
        }
        Command::List => list(&wb)?,
        Command::Analyse { id } => analyse(&wb, id)?,
        Command::Hits { category, text, min_confidence, limit, json } => {
            let categories = category
                .map(|c| serde_json::from_value::<HitCategory>(serde_json::Value::String(c)))
                .transpose()?
                .into_iter()
                .collect();
            let hits = wb.hits(&HitQuery { categories, text, min_confidence, limit, ..Default::default() })?;
            for h in hits {
                if json {
                    println!("{}", serde_json::to_string(&h)?);
                } else {
                    println!(
                        "{} {:>4} {:<12} {:<28} {:<40} {:#x} {}",
                        h.evidence,
                        h.hit.confidence.to_string(),
                        format!("{:?}", h.hit.category),
                        h.hit.label,
                        h.hit.value,
                        h.hit.offset,
                        h.file_path.as_deref().map(|p| format!("{p} [{}]", h.file_state.unwrap_or_default())).unwrap_or_default()
                    );
                }
            }
        }
        Command::Balances { endpoint } => {
            if let Some(url) = endpoint {
                wb.set_chain_endpoint(&url)?;
            }
            println!("endpoint: {}", wb.chain_endpoint());
            for b in wb.balances()? {
                println!("{:<62} {:>14.8} BTC  txs {:<6} {}", b.address, b.balance_btc(), b.tx_count, if b.ever_used() { "USED" } else { "" });
            }
        }
        Command::Correlate => {
            for s in wb.shared_findings()? {
                let disks: Vec<String> = s.evidence.iter().map(|e| e.to_string()).collect();
                println!("{:?}\t{}\t{}\tx{}", s.category, s.value, disks.join(","), s.occurrences);
            }
            for c in wb.file_complements()? {
                let copies: Vec<String> = c.copies.iter().map(|(e, st, sz)| format!("{e}:{st}:{sz}")).collect();
                println!("FILE\t{}\t{}", c.path, copies.join(" "));
            }
        }
    }
    Ok(())
}

fn list(wb: &Workbench) -> Result<(), Box<dyn std::error::Error>> {
    for e in wb.evidence()? {
        let state = wb.case().scan_state(e.id)?;
        println!("{} {} {:?} {} bytes  scan: {:?}", e.id, e.info.label, e.info.kind, e.info.len, state);
        for v in &e.volumes {
            println!("    {} {:?} {:?} @{:#x} {} bytes", v.index, v.fs, v.origin, v.range.start(), v.range.len());
        }
    }
    let counts = wb.hit_counts(None)?;
    if !counts.is_empty() {
        println!("findings: {counts:?}");
    }
    Ok(())
}

fn analyse(wb: &std::sync::Arc<Workbench>, id: Option<u32>) -> Result<(), Box<dyn std::error::Error>> {
    let ids: Vec<EvidenceId> = match id {
        Some(i) => vec![EvidenceId::new(i)],
        None => wb.evidence()?.into_iter().map(|e| e.id).collect(),
    };
    for id in ids {
        wb.analyse(id);
        while wb.has_active_jobs() {
            std::thread::sleep(Duration::from_secs(2));
            for j in wb.jobs().iter().filter(|j| j.state == JobState::Running) {
                let p = &j.progress;
                eprint!(
                    "\r{:<24} {:>6.2}%  {:>8.1} MB/s  hits {:<8}",
                    j.title,
                    j.fraction() * 100.0,
                    p.bytes_per_sec / 1e6,
                    p.hits
                );
            }
        }
        eprintln!();
        for j in wb.jobs().iter().filter(|j| j.evidence == id) {
            println!("{}: {:?}", j.title, j.state);
        }
    }
    Ok(())
}
