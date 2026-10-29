//! Derived knowledge stored with the case: address transaction histories, resolved accounts and
//! ranked leads. Accounts and leads are rebuilt as a whole from findings and events; histories
//! are cached chain lookups. All tables are additive (`CREATE … IF NOT EXISTS`), so older case
//! folders gain them on open.

mod history;
mod inputs;

use crate::Case;
use rusqlite::params;
use strata_accounts::Account;
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

fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

impl Case {
    /// Replace every stored account with a fresh resolution.
    pub fn replace_accounts(&self, accounts: &[Account]) -> Result<usize> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            tx.execute("DELETE FROM accounts", [])?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO accounts (key, service, service_id, service_kind, identifier, kind, first_seen, last_seen, confidence, data)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )?;
                for a in accounts {
                    stmt.execute(params![
                        a.key(),
                        a.service(),
                        a.service_id(),
                        a.service_kind().map(|k| k.label()),
                        a.identifier(),
                        a.kind().label(),
                        a.first_seen().map(|t| t.unix_secs()),
                        a.last_seen().map(|t| t.unix_secs()),
                        a.confidence(),
                        json(a),
                    ])?;
                }
            }
            tx.commit()?;
            Ok(accounts.len())
        })
    }

    /// Stored accounts in resolver order (fund-holding services first).
    pub fn accounts(&self) -> Result<Vec<Account>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT data FROM accounts ORDER BY rowid")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            Ok(rows.filter_map(|r| r.ok()).filter_map(|d| serde_json::from_str(&d).ok()).collect())
        })
    }

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
