//! Job commands: list persisted jobs, analyse (resuming interrupted work first) and `top`.

use std::collections::HashSet;
use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use strata_workbench::{EvidenceId, JobState, JobView, ProcessWatch, ProgressUnit, ResourceSample, SystemSample, Workbench};

type CliResult = Result<(), Box<dyn std::error::Error>>;

fn bytes(n: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let (mut v, mut u) = (n.max(0.0), 0);
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{v:.0} {}", UNITS[u]) } else { format!("{v:.1} {}", UNITS[u]) }
}

fn ago(unix: i64) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    match (now - unix).max(0) {
        s if s < 90 => format!("{s}s ago"),
        s if s < 5400 => format!("{}m ago", s / 60),
        s => format!("{}h ago", s / 3600),
    }
}

fn state(j: &JobView) -> String {
    match &j.state {
        JobState::Running if j.progress.paused => "paused".into(),
        JobState::Running if j.foreign.is_some() => format!("running in pid {}", j.foreign.unwrap_or_default()),
        JobState::Running => "running".into(),
        JobState::Queued => "queued".into(),
        JobState::Done(s) => format!("done — {s}"),
        JobState::Failed(e) => format!("failed — {e}"),
        JobState::Cancelled => "cancelled".into(),
        JobState::Interrupted => "interrupted — will resume".into(),
    }
}

/// `strata-cli jobs`: every persisted job with its state and resume point.
pub fn list(wb: &Workbench) -> CliResult {
    for j in wb.jobs() {
        let resume = j
            .checkpoint
            .as_ref()
            .filter(|_| matches!(j.state, JobState::Interrupted | JobState::Running | JobState::Cancelled))
            .map(|c| format!("  [resumes from {}, saved {}]", c.note, ago(c.saved_at)))
            .unwrap_or_default();
        println!("{:>5} {:<28} {:>5.1}%  {}{resume}", j.id.0, j.title, j.fraction() * 100.0, state(&j));
    }
    Ok(())
}

/// Resume interrupted jobs, then run the pipeline for evidence that was not part of them.
pub fn analyse(wb: &Arc<Workbench>, id: Option<u32>) -> CliResult {
    let before = wb.jobs().last().map_or(0, |j| j.id.0);
    let resumed = wb.resume_interrupted();
    let mut covered = HashSet::new();
    let mut ran: HashSet<u32> = HashSet::new();
    if resumed > 0 {
        eprintln!("resuming {resumed} interrupted jobs");
        for j in wb.jobs().iter().filter(|j| j.state.is_active()) {
            covered.insert(j.evidence);
            ran.insert(j.id.0);
        }
        wait(wb);
    }
    let ids: Vec<EvidenceId> = match id {
        Some(i) => vec![EvidenceId::new(i)],
        None => wb.evidence()?.into_iter().map(|e| e.id).collect(),
    };
    for id in ids.into_iter().filter(|id| !covered.contains(id)) {
        wb.analyse(id)?;
        wait(wb);
    }
    for j in wb.jobs().iter().filter(|j| j.id.0 > before || ran.contains(&j.id.0)) {
        println!("{}: {}", j.title, state(j));
    }
    Ok(())
}

fn wait(wb: &Workbench) {
    while wb.has_active_jobs() {
        std::thread::sleep(Duration::from_secs(2));
        for j in wb.jobs().iter().filter(|j| j.state == JobState::Running) {
            let p = &j.progress;
            let rate = match j.unit {
                ProgressUnit::Bytes => format!("{}/s", bytes(p.per_sec)),
                ProgressUnit::Items => format!("{:.1} items/s", p.per_sec),
            };
            let current: String = j.current.chars().take(40).collect();
            eprint!("\r{:<28} {:>6.2}%  {rate:>14}  hits {:<8} {current:<40}", j.title, j.fraction() * 100.0, p.hits);
        }
    }
    eprintln!();
}

/// `strata-cli top`: what the process running this case's jobs does and costs, refreshed
/// every second. Jobs are re-read from the case, so this works beside a running analysis.
pub fn top(wb: &Workbench, once: bool) -> CliResult {
    let mut watch: Option<(u32, ProcessWatch)> = None;
    loop {
        let records = wb.case().jobs(200)?;
        let owner = records.iter().rev().find(|r| r.state == "Running").and_then(|r| r.owner_pid).unwrap_or(std::process::id());
        let w = match &mut watch {
            Some((pid, w)) if *pid == owner => w,
            slot => {
                let mut w = ProcessWatch::new(owner);
                w.sample();
                &mut slot.insert((owner, w)).1
            }
        };
        std::thread::sleep(Duration::from_secs(1));
        let reading = w.sample();
        let mut out = String::new();
        if !once {
            out.push_str("\x1b[2J\x1b[H");
        }
        out.push_str(&header(owner, reading, w.gpu_available()));
        out.push_str(&format!("\n{:>5} {:<10} {:<28} {:>6}  {}\n", "job", "state", "title", "done", "resumes from"));
        for r in records.iter().rev().take(15) {
            let pct = if r.total > 0 { format!("{:.1}%", r.done as f64 * 100.0 / r.total as f64) } else { "—".into() };
            let note = r
                .checkpoint
                .as_deref()
                .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                .and_then(|v| v.get("note").and_then(|n| n.as_str()).map(str::to_string))
                .map(|n| format!("{n} ({})", ago(r.updated_at)))
                .unwrap_or_default();
            out.push_str(&format!("{:>5} {:<10} {:<28} {:>6}  {note}\n", r.id, r.state.to_lowercase(), r.title, pct));
        }
        print!("{out}");
        std::io::stdout().flush()?;
        if once {
            return Ok(());
        }
    }
}

fn header(pid: u32, reading: Option<(ResourceSample, SystemSample)>, gpu_available: bool) -> String {
    let Some((p, s)) = reading else { return format!("pid {pid}: not running or not readable\n") };
    let gpu = match (gpu_available, p.gpu) {
        (true, Some(g)) => format!("{g:.0}% ({})", p.gpu_memory.map_or("—".into(), |m| bytes(m as f64))),
        _ => "not available".into(),
    };
    format!(
        "pid {pid}  CPU {:.0}%  RAM {} (private {})  read {}/s  write {}/s  threads {}  GPU {gpu}\nsystem  CPU {:.0}%  free RAM {} of {}\n",
        p.cpu,
        bytes(p.working_set as f64),
        bytes(p.private_bytes as f64),
        bytes(p.read_per_sec),
        bytes(p.write_per_sec),
        p.threads.map_or("—".into(), |t| t.to_string()),
        s.cpu,
        bytes(s.free_ram as f64),
        bytes(s.total_ram as f64),
    )
}
