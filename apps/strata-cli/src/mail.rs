//! `mail` and `mail-show` subcommands.

use std::path::Path;
use strata_workbench::{MessageQuery, Workbench};

type Res = Result<(), Box<dyn std::error::Error>>;

pub fn list(wb: &Workbench, text: Option<String>, address: Option<String>, limit: usize, json: bool) -> Res {
    let q = MessageQuery { text, address, limit, ..MessageQuery::default() };
    let rows = wb.messages(&q)?;
    for m in &rows {
        if json {
            println!("{}", serde_json::to_string(m)?);
            continue;
        }
        let at = m.at.map_or_else(|| "undated".to_string(), |t| t.to_string());
        let copies = if m.copies > 0 { format!(" (+{} copies)", m.copies) } else { String::new() };
        println!(
            "{:>6} {} {:<19} {:<8} {:<32} {:<32} {}  [{}]{copies}",
            m.id,
            m.evidence,
            at,
            m.location.state.name(),
            m.from,
            m.to,
            m.subject,
            m.location.describe()
        );
    }
    let total = wb.message_count(&MessageQuery { limit: 0, ..q })?;
    if !json {
        println!("{} of {total} messages", rows.len());
    }
    Ok(())
}

pub fn show(wb: &Workbench, id: i64, json: bool, export: Option<&Path>) -> Res {
    let m = wb.message(id)?.ok_or(format!("no message {id}"))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&m)?);
    } else {
        for (name, value) in &m.message.headers {
            println!("{name}: {value}");
        }
        println!();
        println!("{}", m.message.body);
        println!();
        for (i, a) in m.message.attachments.iter().enumerate() {
            println!("attachment {}: {} ({}, {} bytes)", i + 1, a.name, a.mime, a.size);
        }
        println!("found: {} ({})", m.row.location.describe(), m.row.location.state.name());
        for p in &m.places {
            println!("also:  {} ({})", p.describe(), p.state.name());
        }
        for n in &m.message.notes {
            println!("note:  {n}");
        }
    }
    if let Some(dir) = export {
        println!("written {}", wb.export_message(id, dir)?.written_to.display());
        for i in 0..m.message.attachments.len() {
            let r = wb.export_attachment(id, i, dir)?;
            println!("written {}{}", r.written_to.display(), if r.partial { " (partial)" } else { "" });
        }
    }
    Ok(())
}
