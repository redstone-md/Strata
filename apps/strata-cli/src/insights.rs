//! `leads`, `accounts` and `services` subcommands.

use strata_workbench::{Catalogue, Workbench};

type Res = Result<(), Box<dyn std::error::Error>>;

fn day(t: Option<strata_workbench::Timestamp>) -> String {
    t.map(|t| t.to_string()[..10].to_string()).unwrap_or_else(|| "?".into())
}

pub fn leads(wb: &Workbench, rebuild: bool, fetch: bool, limit: usize, json: bool) -> Res {
    if fetch {
        let (ok, failed) = wb.fetch_histories()?;
        eprintln!("{ok} histories fetched, {failed} failed");
    } else if rebuild {
        let (a, l) = wb.rebuild_insights()?;
        eprintln!("{a} accounts, {l} leads");
    }
    for l in wb.leads()?.into_iter().take(limit) {
        if json {
            println!("{}", serde_json::to_string(&l)?);
            continue;
        }
        let window = l.window.map(|(a, b)| format!("{} .. {}", day(Some(a)), day(Some(b)))).unwrap_or_default();
        println!("{:>5.1}  {}  [{}]  {window}", l.score, l.title, l.rule.label());
        for sentence in &l.explanation {
            println!("        {sentence}");
        }
        println!();
    }
    Ok(())
}

pub fn accounts(wb: &Workbench, rebuild: bool, funds: bool, json: bool) -> Res {
    if rebuild {
        let (a, l) = wb.rebuild_insights()?;
        eprintln!("{a} accounts, {l} leads");
    }
    for a in wb.accounts()?.into_iter().filter(|a| !funds || a.holds_funds()) {
        if json {
            println!("{}", serde_json::to_string(&a)?);
            continue;
        }
        let kind = a.service_kind().map_or("", |k| k.label());
        let disks: Vec<String> = a.disks().iter().map(|d| d.to_string()).collect();
        println!(
            "{:<28} {:<18} {:<40} {:<8} {} .. {}  {:>3.0}%  disks {}  traces {}",
            a.service(),
            kind,
            a.identifier(),
            a.kind().label(),
            day(a.first_seen()),
            day(a.last_seen()),
            a.confidence() * 100.0,
            disks.join(","),
            a.sources().len()
        );
    }
    Ok(())
}

pub fn services(all: bool) {
    let c = Catalogue::shared();
    println!("catalogue v{}: {} services", c.version(), c.entries().len());
    for (kind, n) in c.count_by_kind() {
        println!("  {:<24} {n}", kind.label());
    }
    if all {
        for e in c.entries() {
            let years = e.years().map(|y| y.to_string()).unwrap_or_default();
            println!("{:<22} {:<16} {:<44} {:<12} {}", e.id(), e.kind().label(), e.name(), years, e.domains().join(" "));
        }
    }
}
