//! Writing messages: one row per message and disk, merged by fingerprint. The best copy (live
//! over deleted over carved) keeps the row; the others become its places.

use super::{FoundMessage, MessageLocation};
use rusqlite::{Connection, OptionalExtension, params};
use strata_kernel::EvidenceId;
use strata_mail::{Message, join};

/// What a batch did: messages added as new rows, and copies merged into existing ones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stored {
    pub added: usize,
    pub merged: usize,
}

pub(crate) fn clear(conn: &Connection, id: EvidenceId) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM message_addresses WHERE message IN (SELECT id FROM messages WHERE evidence_id = ?1)", [id.get()])?;
    conn.execute("DELETE FROM messages WHERE evidence_id = ?1", [id.get()])?;
    Ok(())
}

pub(crate) fn insert(conn: &Connection, id: EvidenceId, found: &[FoundMessage]) -> rusqlite::Result<Stored> {
    let mut out = Stored::default();
    for f in found {
        let fingerprint = f.message.envelope.fingerprint();
        let existing: Option<(i64, String, String)> = conn
            .query_row(
                "SELECT m.id, json_object('state', m.state, 'container', m.container, 'volume', m.volume_idx, 'file_idx', m.file_idx,
                        'path', m.file_path, 'offset', m.offset, 'len', m.len), m.places
                 FROM messages m WHERE m.evidence_id = ?1 AND m.fingerprint = ?2",
                params![id.get(), fingerprint],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((row, current, places)) = existing else {
            write_new(conn, id, &fingerprint, f)?;
            out.added += 1;
            continue;
        };
        let current: Option<MessageLocation> = serde_json::from_str(&current).ok();
        let mut places: Vec<MessageLocation> = serde_json::from_str(&places).unwrap_or_default();
        if current.as_ref().is_some_and(|c| c.same_place(&f.location)) || places.iter().any(|p| p.same_place(&f.location)) {
            continue;
        }
        out.merged += 1;
        match current {
            Some(current) if f.location.state > current.state => {
                places.push(current);
                replace(conn, row, f, &places)?;
            }
            _ => {
                places.push(f.location.clone());
                conn.execute("UPDATE messages SET places = ?2 WHERE id = ?1", params![row, json(&places)])?;
            }
        }
    }
    Ok(out)
}

fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// The message without its body (the body has a column of its own).
fn data(m: &Message) -> String {
    json(&Message { body: String::new(), ..m.clone() })
}

fn recipients(m: &Message) -> String {
    let (to, cc) = (join(&m.envelope.to), join(&m.envelope.cc));
    if cc.is_empty() { to } else { format!("{to}, {cc}") }
}

fn write_new(conn: &Connection, id: EvidenceId, fingerprint: &str, f: &FoundMessage) -> rusqlite::Result<()> {
    let (l, m) = (&f.location, &f.message);
    conn.prepare_cached(
        "INSERT INTO messages (evidence_id, fingerprint, state, container, volume_idx, file_idx, file_path, folder, offset, len,
         at, message_id, sender, recipients, subject, body, attachments, data, places)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, '[]')",
    )?
    .execute(params![
        id.get(),
        fingerprint,
        l.state.name(),
        l.container.name(),
        l.volume,
        l.file_idx.map(|i| i as i64),
        l.path,
        f.folder,
        l.offset as i64,
        l.len as i64,
        m.envelope.date.map(|d| d.unix_secs()),
        m.envelope.message_id,
        join(&m.envelope.from),
        recipients(m),
        m.envelope.subject,
        m.body,
        m.attachments.len() as i64,
        data(m),
    ])?;
    let message = conn.last_insert_rowid();
    let mut stmt = conn.prepare_cached("INSERT OR IGNORE INTO message_addresses (address, message) VALUES (?1, ?2)")?;
    for a in m.envelope.addresses() {
        stmt.execute(params![a, message])?;
    }
    Ok(())
}

/// A better copy of a stored message takes over its row.
fn replace(conn: &Connection, row: i64, f: &FoundMessage, places: &[MessageLocation]) -> rusqlite::Result<()> {
    let (l, m) = (&f.location, &f.message);
    conn.execute(
        "UPDATE messages SET state = ?2, container = ?3, volume_idx = ?4, file_idx = ?5, file_path = ?6, folder = ?7, offset = ?8,
         len = ?9, body = ?10, attachments = ?11, data = ?12, places = ?13, sender = ?14, recipients = ?15, subject = ?16 WHERE id = ?1",
        params![
            row,
            l.state.name(),
            l.container.name(),
            l.volume,
            l.file_idx.map(|i| i as i64),
            l.path,
            f.folder,
            l.offset as i64,
            l.len as i64,
            m.body,
            m.attachments.len() as i64,
            data(m),
            json(&places),
            join(&m.envelope.from),
            recipients(m),
            m.envelope.subject,
        ],
    )?;
    let mut stmt = conn.prepare_cached("INSERT OR IGNORE INTO message_addresses (address, message) VALUES (?1, ?2)")?;
    for a in m.envelope.addresses() {
        stmt.execute(params![a, row])?;
    }
    Ok(())
}
