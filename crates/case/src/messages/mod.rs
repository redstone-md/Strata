//! Recovered e-mail messages: where each was found (a live or deleted mail file, or free space),
//! its envelope, body and attachment list. The same message found twice on a disk (same
//! Message-ID and date, e.g. the live inbox and a carved copy in free space) is one row that
//! lists the other places.

mod store;

use crate::Case;
use rusqlite::Row;
use serde::{Deserialize, Serialize};
use strata_kernel::{EvidenceId, Result, Timestamp};
use strata_mail::{Container, Message};

pub(crate) use store::{clear, insert};
pub use store::Stored as StoredBatch;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    fingerprint TEXT NOT NULL,
    state TEXT NOT NULL,
    container TEXT NOT NULL,
    volume_idx INTEGER,
    file_idx INTEGER,
    file_path TEXT,
    folder TEXT NOT NULL,
    offset INTEGER NOT NULL,
    len INTEGER NOT NULL,
    at INTEGER,
    message_id TEXT,
    sender TEXT NOT NULL,
    recipients TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    attachments INTEGER NOT NULL,
    data TEXT NOT NULL,
    places TEXT NOT NULL,
    UNIQUE (evidence_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS messages_at ON messages(at);
CREATE INDEX IF NOT EXISTS messages_evidence ON messages(evidence_id, at);

CREATE TABLE IF NOT EXISTS message_addresses (
    address TEXT NOT NULL,
    message INTEGER NOT NULL,
    PRIMARY KEY (address, message)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS message_addresses_message ON message_addresses(message);
"#;

/// How a message was found. Ordered from least to most trustworthy copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageState {
    /// Cut out of free space, outside any file.
    Carved,
    /// Inside a deleted mail file.
    Deleted,
    /// Inside a live mail file.
    Live,
}

impl MessageState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Deleted => "deleted",
            Self::Carved => "carved",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Live, Self::Deleted, Self::Carved].into_iter().find(|v| v.name() == s)
    }
}

/// Where a message's bytes are: inside a file (offset and length in it; for `.dbx` the first
/// chunk of its chain) or, carved, on the disk itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageLocation {
    pub state: MessageState,
    pub container: Container,
    pub volume: Option<u32>,
    pub file_idx: Option<usize>,
    pub path: Option<String>,
    pub offset: u64,
    pub len: u64,
}

impl MessageLocation {
    /// `Inbox.dbx +0x2400` or `free space 0x1F000`.
    pub fn describe(&self) -> String {
        match &self.path {
            Some(p) => format!("{p} +{:#x}", self.offset),
            None => format!("free space {:#x}", self.offset),
        }
    }

    fn same_place(&self, other: &Self) -> bool {
        self.volume == other.volume && self.file_idx == other.file_idx && self.path == other.path && self.offset == other.offset
    }
}

/// One message as the list shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageRow {
    pub id: i64,
    pub evidence: EvidenceId,
    pub location: MessageLocation,
    /// Mailbox folder: the mbox / `.dbx` file name, the folder of an `.eml`; empty when carved.
    pub folder: String,
    pub at: Option<Timestamp>,
    pub from: String,
    /// To and Cc.
    pub to: String,
    pub subject: String,
    pub attachments: usize,
    /// Other places the same message was found on this disk.
    pub copies: usize,
}

/// One message with everything stored about it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredMessage {
    pub row: MessageRow,
    pub message: Message,
    pub places: Vec<MessageLocation>,
}

/// A message to store: where it was found, its folder and the parsed message.
#[derive(Debug, Clone)]
pub struct FoundMessage {
    pub location: MessageLocation,
    pub folder: String,
    pub message: Message,
}

#[derive(Debug, Clone, Default)]
pub struct MessageQuery {
    pub evidence: Option<EvidenceId>,
    /// Anywhere in subject, sender, recipients or body.
    pub text: Option<String>,
    /// Messages from, to or copying this address.
    pub address: Option<String>,
    pub from: Option<Timestamp>,
    pub to: Option<Timestamp>,
    pub state: Option<MessageState>,
    pub limit: usize,
    pub offset: usize,
}

impl MessageQuery {
    /// `WHERE` clause and its arguments.
    fn filter(&self) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
        let mut sql = String::from(" WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut add = |clause: &str, value: Box<dyn rusqlite::ToSql>| {
            args.push(value);
            sql += &clause.replace("{n}", &args.len().to_string());
        };
        if let Some(e) = self.evidence {
            add(" AND evidence_id = ?{n}", Box::new(e.get()));
        }
        if let Some(t) = self.text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            let like = format!("%{}%", t.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
            add(
                " AND (subject LIKE ?{n} ESCAPE '\\' OR sender LIKE ?{n} ESCAPE '\\' OR recipients LIKE ?{n} ESCAPE '\\' OR body LIKE ?{n} ESCAPE '\\')",
                Box::new(like),
            );
        }
        if let Some(a) = self.address.as_deref().map(str::trim).filter(|a| !a.is_empty()) {
            add(" AND id IN (SELECT message FROM message_addresses WHERE address = ?{n})", Box::new(a.to_ascii_lowercase()));
        }
        if let Some(t) = self.from {
            add(" AND at >= ?{n}", Box::new(t.unix_secs()));
        }
        if let Some(t) = self.to {
            add(" AND at < ?{n}", Box::new(t.unix_secs()));
        }
        if let Some(s) = self.state {
            add(" AND state = ?{n}", Box::new(s.name()));
        }
        (sql, args)
    }
}

const ROW_COLUMNS: &str =
    "id, evidence_id, state, container, volume_idx, file_idx, file_path, offset, len, folder, at, sender, recipients, subject, attachments, places";

fn row(r: &Row<'_>) -> rusqlite::Result<(MessageRow, Vec<MessageLocation>)> {
    let state: String = r.get(2)?;
    let container: String = r.get(3)?;
    let places: Vec<MessageLocation> = serde_json::from_str(&r.get::<_, String>(15)?).unwrap_or_default();
    let location = MessageLocation {
        state: MessageState::parse(&state).unwrap_or(MessageState::Carved),
        container: Container::parse(&container).unwrap_or(Container::Carved),
        volume: r.get(4)?,
        file_idx: r.get::<_, Option<i64>>(5)?.map(|i| i as usize),
        path: r.get(6)?,
        offset: r.get::<_, i64>(7)? as u64,
        len: r.get::<_, i64>(8)? as u64,
    };
    let row = MessageRow {
        id: r.get(0)?,
        evidence: EvidenceId::new(r.get(1)?),
        location,
        folder: r.get(9)?,
        at: r.get::<_, Option<i64>>(10)?.and_then(Timestamp::from_unix_secs),
        from: r.get(11)?,
        to: r.get(12)?,
        subject: r.get(13)?,
        attachments: r.get::<_, i64>(14)? as usize,
        copies: places.len(),
    };
    Ok((row, places))
}

impl Case {
    /// Messages matching `q`, oldest first (undated last), paged by `limit`/`offset`.
    pub fn messages(&self, q: &MessageQuery) -> Result<Vec<MessageRow>> {
        let (filter, args) = q.filter();
        let mut sql = format!("SELECT {ROW_COLUMNS} FROM messages{filter} ORDER BY at IS NULL, at, id");
        if q.limit > 0 {
            sql += &format!(" LIMIT {} OFFSET {}", q.limit, q.offset);
        }
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(args.iter().map(|a| a.as_ref())), |r| row(r).map(|(row, _)| row))?;
            rows.collect()
        })
    }

    /// How many messages match `q` (paging ignored).
    pub fn message_count(&self, q: &MessageQuery) -> Result<u64> {
        let (filter, args) = q.filter();
        self.with_conn(|conn| {
            conn.query_row(&format!("SELECT COUNT(*) FROM messages{filter}"), rusqlite::params_from_iter(args.iter().map(|a| a.as_ref())), |r| {
                r.get::<_, i64>(0)
            })
        })
        .map(|n| n as u64)
    }

    /// One message with body, headers, attachments and every place it was found.
    pub fn message(&self, id: i64) -> Result<Option<StoredMessage>> {
        use rusqlite::OptionalExtension;
        self.with_conn(|conn| {
            conn.query_row(&format!("SELECT {ROW_COLUMNS}, body, data FROM messages WHERE id = ?1"), [id], |r| {
                let (row, places) = row(r)?;
                let mut message: Message = serde_json::from_str(&r.get::<_, String>(17)?).unwrap_or_default();
                message.body = r.get(16)?;
                Ok(StoredMessage { row, message, places })
            })
            .optional()
        })
    }
}

#[cfg(test)]
mod tests;
