//! Headless front-end for long unattended runs and scripting.

mod insights;
mod jobs;
mod machines;
mod mail;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use strata_workbench::{Encoding, EventQuery, EvidenceId, HitCategory, HitQuery, JobKind, JobState, Pattern, Scope, SearchQuery, Workbench};

#[derive(Parser)]
#[command(name = "strata-cli", version, about = "Strata forensic workbench (headless)")]
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
    Add {
        location: String,
        /// Also probe old CHS cylinder starts and ends for deleted partitions.
        #[arg(long)]
        deep: bool,
    },
    /// List evidence and volumes.
    List,
    /// Run the whole analysis pipeline. Interrupted jobs (a crash, a closed app) resume from
    /// their checkpoints first; evidence they covered is not started again.
    Analyse {
        /// Evidence id; all evidence when omitted.
        id: Option<u32>,
        /// Detector threads (saved in the case; default 3).
        #[arg(long)]
        threads: Option<usize>,
    },
    /// Run a single step: IndexFiles, Scan, RecoverPartitions, Artifacts, Mail, ClassifyFiles, Archives, Carve, CheckBalances, Triage.
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
    /// Recovered e-mail (the Mail step): live, deleted and carved messages, oldest first.
    Mail {
        /// Anywhere in subject, sender, recipients or body.
        #[arg(long)]
        text: Option<String>,
        /// Messages from, to or copying this address.
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// One message: headers, body, attachments and every place it was found.
    MailShow {
        id: i64,
        #[arg(long)]
        json: bool,
        /// Also write the message (.eml) and its attachments to this folder.
        #[arg(long)]
        export: Option<PathBuf>,
    },
    /// Host facts: computer name, users, USB devices, wallet folders...
    Facts,
    /// The computers each disk held: one profile per installation (OS, owner, users, time
    /// zone, network, hardware, USB devices, crypto software) and when it was in use.
    Machines {
        /// Only this disk id.
        #[arg(long)]
        disk: Option<u32>,
        #[arg(long)]
        json: bool,
    },
    /// When each disk was in use: first and last day, active periods, typical hours.
    Usage {
        #[arg(long)]
        disk: Option<u32>,
        #[arg(long)]
        json: bool,
    },
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
    /// Search disk content (deleted data included) for text, hex bytes or a regex.
    Search {
        /// Evidence id, or `all`.
        id: String,
        pattern: String,
        /// The pattern is hex bytes (`4D 5A 90 00`).
        #[arg(long)]
        hex: bool,
        /// The pattern is a regular expression (slower; UTF-16 runs decoded when selected).
        #[arg(long)]
        regex: bool,
        /// disk | unallocated | deleted | volume:N
        #[arg(long, default_value = "disk")]
        scope: String,
        /// Comma-separated: utf8, ascii, cp1251, cp866, utf16le, utf16be.
        #[arg(long, default_value = "utf8,utf16le,cp1251")]
        enc: String,
        #[arg(long)]
        case_sensitive: bool,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Find files by name on every disk, deleted and orphaned entries included (`*`, `?` glob).
    Names {
        pattern: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Show looked-up address balances; `--endpoint` changes the Esplora server.
    Balances {
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Ranked leads: what may fit where (on-chain activity, accounts, wallet file times).
    Leads {
        /// Re-run the lead engine first (no network).
        #[arg(long)]
        rebuild: bool,
        /// Fetch missing on-chain histories of used addresses first (network), then rebuild.
        #[arg(long)]
        fetch: bool,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Accounts per service, merged across findings, artefacts and disks.
    Accounts {
        #[arg(long)]
        rebuild: bool,
        /// Only services that hold funds (exchanges, web wallets, faucets, pools, dice...).
        #[arg(long)]
        funds: bool,
        #[arg(long)]
        json: bool,
    },
    /// The service catalogue: counts per kind, or every entry with --all.
    Services {
        #[arg(long)]
        all: bool,
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
        Command::Add { location, deep } => {
            let r = if deep { wb.add_evidence_deep(&location)? } else { wb.add_evidence(&location)? };
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
        Command::Analyse { id, threads } => {
            if let Some(t) = threads {
                wb.set_scan_threads(t)?;
            }
            jobs::analyse(&wb, id)?
        }
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
        Command::Mail { text, address, limit, json } => mail::list(&wb, text, address, limit, json)?,
        Command::MailShow { id, json, export } => mail::show(&wb, id, json, export.as_deref())?,
        Command::Facts => {
            for f in wb.host_facts(None)? {
                println!("{} {:<24} {}  ({})", f.evidence, f.key, f.value, f.source);
            }
        }
        Command::Machines { disk, json } => machines::machines(&wb, disk, json)?,
        Command::Usage { disk, json } => machines::usage(&wb, disk, json)?,
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
        Command::Search { id, pattern, hex, regex, scope, enc, case_sensitive, limit } => {
            let query = SearchQuery {
                pattern: if hex {
                    Pattern::hex(&pattern)?
                } else if regex {
                    Pattern::Regex(pattern)
                } else {
                    Pattern::Text(pattern)
                },
                encodings: enc.split(',').map(|e| Encoding::from_key(e).ok_or(format!("unknown encoding {e}"))).collect::<Result<_, _>>()?,
                case_insensitive: !case_sensitive,
                scope: Scope::parse(&scope).ok_or(format!("unknown scope {scope}"))?,
            };
            let evidence = if id.eq_ignore_ascii_case("all") { None } else { Some(EvidenceId::new(id.parse()?)) };
            search(&wb, query, evidence, limit)?;
        }
        Command::Names { pattern, limit } => {
            for f in wb.find_files_by_name(&pattern, None, limit)? {
                println!("{} v{} {:<9} {:>12}  {}", f.evidence, f.volume, f.state, f.size, f.path);
            }
        }
        Command::Leads { rebuild, fetch, limit, json } => insights::leads(&wb, rebuild, fetch, limit, json)?,
        Command::Accounts { rebuild, funds, json } => insights::accounts(&wb, rebuild, funds, json)?,
        Command::Services { all } => insights::services(all),
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

fn search(wb: &std::sync::Arc<Workbench>, query: SearchQuery, evidence: Option<EvidenceId>, limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("searching {}", query.summary());
    let (_, search) = wb.start_search(query, evidence)?;
    while wb.has_active_jobs() {
        std::thread::sleep(Duration::from_millis(500));
        for j in wb.jobs().iter().filter(|j| j.state == JobState::Running) {
            eprint!("\r{:>6.2}%  {:>8.1} MB/s  matches {:<8}", j.fraction() * 100.0, j.progress.per_sec / 1e6, j.progress.hits);
        }
    }
    eprintln!();
    let record = wb.search_record(search)?.ok_or("search vanished")?;
    for r in wb.search_results(search, 0, limit)? {
        let place = r.file_path.as_deref().map_or("free space".to_string(), |p| format!("{p} +{:#x}", r.file_offset.unwrap_or(0)));
        println!("{} {:#012x} {:<9} {:<17} {:<40} {}", r.evidence, r.offset, r.encoding, r.location, place, r.preview);
    }
    let more = if record.truncated { " (limit reached, more exist)" } else { "" };
    println!("{}: {} matches{more}", record.state, record.results);
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
    let counts = wb.hit_counts(None, 0.0)?;
    if !counts.is_empty() {
        println!("findings: {counts:?}");
    }
    Ok(())
}
