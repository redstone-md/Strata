//! Derived knowledge stored with the case: address transaction histories, resolved accounts and
//! ranked leads. Accounts and leads are rebuilt as a whole from findings and events; histories
//! are cached chain lookups. All tables are additive (`CREATE … IF NOT EXISTS`), so older case
//! folders gain them on open.

mod accounts;
mod history;
mod inputs;
mod mailboxes;
mod mentions;

pub use accounts::{AccountQuery, AccountRow};
pub(crate) use accounts::ACCOUNT_TRACE_HITS;
pub use mailboxes::MailboxTrace;
pub use mentions::Mention;

use crate::Case;
use rusqlite::params;
use strata_kernel::Result;
use strata_leads::Lead;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS address_history (
    address TEXT PRIMARY KEY,
    first_seen INTEGER,
    last_seen INTEGER,
    tx_count INTEGER NOT NULL,
    complete INTEGER NOT NULL,
    data TEXT NOT NULL,
    checked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    key TEXT PRIMARY KEY,
    service TEXT NOT NULL,
    service_id TEXT,
    service_kind TEXT,
    identifier TEXT NOT NULL,
    kind TEXT NOT NULL,
    first_seen INTEGER,
    last_seen INTEGER,
    confidence REAL NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS accounts_identifier ON accounts(identifier);

-- Addresses found by the byte-level e-mail detector, one row per case-folded address:
-- how often, in how many places, on which disks, and how crowded its least crowded place is
-- (`density`: distinct addresses in that file or MiB of free space; see BULK_PLACE_ADDRESSES).
CREATE TABLE IF NOT EXISTS account_mentions (
    address TEXT PRIMARY KEY,
    found_as TEXT NOT NULL,
    hits INTEGER NOT NULL,
    places INTEGER NOT NULL,
    disks TEXT NOT NULL,
    density INTEGER NOT NULL,
    sample INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS account_mentions_density ON account_mentions(density, hits);
-- The findings `account_mentions` was built from (max hit id and disk count).
CREATE TABLE IF NOT EXISTS account_mentions_state (id INTEGER PRIMARY KEY CHECK (id = 1), fingerprint TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS leads (
    id TEXT PRIMARY KEY,
    rule TEXT NOT NULL,
    score REAL NOT NULL,
    title TEXT NOT NULL,
    window_from INTEGER,
    window_to INTEGER,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS leads_score ON leads(score);
"#;

pub(crate) fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

impl Case {
    /// Replace every stored lead.
    pub fn replace_leads(&self, leads: &[Lead]) -> Result<usize> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            tx.execute("DELETE FROM leads", [])?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO leads (id, rule, score, title, window_from, window_to, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )?;
                for l in leads {
                    stmt.execute(params![
                        l.id,
                        format!("{:?}", l.rule),
                        l.score,
                        l.title,
                        l.window.map(|w| w.0.unix_secs()),
                        l.window.map(|w| w.1.unix_secs()),
                        json(l),
                    ])?;
                }
            }
            tx.commit()?;
            Ok(leads.len())
        })
    }

    /// Stored leads, best first.
    pub fn leads(&self) -> Result<Vec<Lead>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT data FROM leads ORDER BY score DESC, id")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            Ok(rows.filter_map(|r| r.ok()).filter_map(|d| serde_json::from_str(&d).ok()).collect())
        })
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod account_tests;
