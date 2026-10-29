//! Headless front-end for long unattended runs and scripting.

mod jobs;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use strata_workbench::{EventQuery, EvidenceId, HitCategory, HitQuery, JobKind, Workbench};

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
    /// Run the whole analysis pipeline. Interrupted jobs (a crash, a closed app) resume from
    /// their checkpoints first; evidence they covered is not started again.
    Analyse {
        /// Evidence id; all evidence when omitted.
        id: Option<u32>,
    },
    /// Run a single step: IndexFiles, Scan, Artifacts, ClassifyFiles, Archives, Carve, CheckBalances, Triage.
    Step { kind: String, id: u32 },
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
        /// One line per distinct value with the number of places it was found.
        #[arg(long)]
        group: bool,
    },
    /// Findings shared between disks and files that differ across disks.
    Correlate,
    /// Export a report: md (Russian), html, csv, json.
    Report {
        #[arg(default_value = "html")]
        format: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Print the timeline (artefacts; add --with-fs for filesystem times).
    Timeline {
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        crypto: bool,
        #[arg(long)]
        with_fs: bool,
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
    /// Host facts: computer name, users, USB devices, wallet folders...
    Facts,
    /// Passwords of your own archives, tried on encrypted ZIP members by the Archives step.
    /// With arguments the list is replaced; without, it is printed.
    ArchivePasswords { passwords: Vec<String> },
    /// Members unpacked from archives by the Archives step.
    Members { id: u32 },
    /// Jobs stored in the case: state, progress and where interrupted ones resume.
    Jobs,
    /// Live view of the process running this case's jobs: CPU, memory, disk I/O, GPU, jobs.
    Top {
        /// Print one frame and exit.
        #[arg(long)]
        once: bool,
    },
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
    // Nothing resumes behind the user's back here; `analyse` resumes explicitly.
    let wb = Workbench::open_idle(&cli.case)?;
    match cli.command {
        Command::Add { location } => {
            let r = wb.add_evidence(&location)?;
            println!("added {} {} ({} bytes, {} volumes)", r.id, r.info.label, r.info.len, r.volumes.len());
        }
        Command::List => list(&wb)?,
        Command::Step { kind, id } => {
            let id = EvidenceId::new(id);
            if kind.eq_ignore_ascii_case("triage") {
                println!("{} findings downgraded", wb.triage(id)?);
            } else if kind.eq_ignore_ascii_case("reattribute") {
                let (n, t) = wb.reattribute(id)?;
                println!("{n} findings re-mapped, {t} downgraded");
            } else {
                let kind: JobKind = serde_json::from_value(serde_json::Value::String(kind))?;
                let view = wb.run_step(kind, id)?;
                println!("{}: {:?}", view.title, view.state);
            }
        }
        Command::Analyse { id } => jobs::analyse(&wb, id)?,
        Command::Jobs => jobs::list(&wb)?,
        Command::Top { once } => jobs::top(&wb, once)?,
        Command::Hits { category, text, min_confidence, limit, json, group } => {
            let categories = category
                .map(|c| serde_json::from_value::<HitCategory>(serde_json::Value::String(c)))
                .transpose()?
                .into_iter()
                .collect();
            let hits = wb.hits(&HitQuery { categories, text, min_confidence, limit, group_by_value: group, ..Default::default() })?;
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
        Command::Report { format, out } => {
            let dir = out.unwrap_or_else(|| cli.case.join("reports"));
            println!("{}", wb.export_report(&format, &dir)?.display());
        }
        Command::Timeline { text, crypto, with_fs, limit } => {
            let q = EventQuery { text, crypto_only: crypto, skip_filesystem: !with_fs, limit, ..Default::default() };
            for (ev, e) in wb.events(&q)? {
                let deleted = if e.source().deleted { " [deleted]" } else { "" };
                println!("{} {} {:<16} {}  ({}{deleted})", e.at(), ev, format!("{:?}", e.kind()), e.title(), e.source().path);
            }
        }
        Command::Facts => {
            for f in wb.host_facts(None)? {
                println!("{} {:<24} {}  ({})", f.evidence, f.key, f.value, f.source);
            }
        }
        Command::ArchivePasswords { passwords } => {
            if !passwords.is_empty() {
                wb.set_archive_passwords(&passwords)?;
            }
            println!("{} archive passwords set", wb.archive_passwords().len());
        }
        Command::Members { id } => {
            for m in wb.case().archive_members(EvidenceId::new(id))? {
                let flags = format!("{}{}", if m.encrypted { "E" } else { "-" }, if m.extension_mismatch { "R" } else { "-" });
                println!(
                    "{flags} {:>12} {:<24} {} {}",
                    m.recovered,
                    m.detected_type.as_deref().unwrap_or("?"),
                    m.member_path,
                    if m.damage == "[]" { String::new() } else { m.damage.clone() }
                );
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
