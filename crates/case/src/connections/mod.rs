//! What the connection graph is built from, read from the case with aggregated and capped
//! queries (never every finding: real cases hold millions of identity rows), plus a cheap
//! stamp that changes when any of it may have changed.

mod findings;
mod mail;

use crate::Case;
use std::collections::BTreeSet;
use strata_chain::AddressHistory;
use strata_graph::{ChainFact, DiskFact, Facts, Limits, TxFact};
use strata_kernel::{Result, Timestamp};

impl Case {
    /// Facts for [`strata_graph::GraphBuilder`]: secrets and what sits beside them, artefact
    /// identities, used addresses, accounts, chain data, mail, mentions and leads, each bounded
    /// by `limits`. Takes seconds on a large case; call it off the UI thread. `step` is told
    /// what is being read, for a progress line.
    pub fn connection_facts(&self, limits: &Limits, step: &dyn Fn(&'static str)) -> Result<Facts> {
        let disks = self.evidence()?.into_iter().map(|e| DiskFact { id: e.id, label: e.info.label }).collect();
        let mut facts = self.with_conn(|conn| {
            step("Reading keys, seeds and wallets");
            let secrets = findings::secrets(conn, limits)?;
            step("Reading what sits beside them");
            let beside = findings::beside(conn, &secrets, limits)?;
            step("Reading addresses used on chain");
            let used = findings::used_addresses(conn, limits)?;
            let mut seen = BTreeSet::new();
            let all = secrets.into_iter().chain(beside).chain(used).filter(|f| seen.insert(f.hit)).collect();
            step("Reading balances, mail and accounts");
            Ok(Facts { findings: all, chain: chain(conn)?, mail: mail::messages(conn, limits)?, accounts: accounts(conn, limits)?, ..Facts::default() })
        })?;
        facts.disks = disks;
        step("Reading leads");
        facts.leads = self.leads()?.into_iter().take(limits.leads).collect();
        let values = facts.identity_values(limits.spreads);
        let targets = facts.mention_targets();
        step("Checking how widely each identity is spread");
        let spreads = self.with_conn(|conn| findings::spreads(conn, &values, limits))?;
        step("Searching mail for known addresses and keys");
        let mentions = self.with_conn(|conn| mail::mentions(conn, &targets, limits))?;
        facts.spreads = spreads;
        facts.mentions = mentions;
        Ok(facts)
    }

    /// Changes whenever findings, accounts, leads, mail, chain data or disks change: a graph
    /// built at an equal stamp is still current. Uses row counts and the largest row ids
    /// (rebuilt rows get new ones), which SQLite reads without scanning the tables.
    pub fn connection_stamp(&self) -> Result<String> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT (SELECT IFNULL(MAX(id), 0) FROM hits) || ':' || (SELECT IFNULL(MAX(rowid), 0) FROM accounts)
                     || ':' || (SELECT IFNULL(MAX(rowid), 0) FROM leads) || ':' || (SELECT IFNULL(MAX(id), 0) FROM messages)
                     || ':' || (SELECT IFNULL(MAX(rowid), 0) FROM balances) || ':' || (SELECT IFNULL(MAX(rowid), 0) FROM address_history)
                     || ':' || (SELECT COUNT(*) FROM evidence)",
                [],
                |r| r.get(0),
            )
        })
    }
}

/// Stored accounts in resolver order (fund-holding services first), mailboxes left out.
fn accounts(conn: &rusqlite::Connection, limits: &Limits) -> rusqlite::Result<Vec<strata_accounts::Account>> {
    let mut stmt = conn.prepare("SELECT data FROM accounts WHERE NOT (IFNULL(service_kind, '') = 'mail' AND kind = 'e-mail') ORDER BY rowid LIMIT ?1")?;
    let rows = stmt.query_map([limits.accounts as i64], |r| r.get::<_, String>(0))?;
    Ok(rows.filter_map(|r| r.ok()).filter_map(|d| serde_json::from_str(&d).ok()).collect())
}

/// Every looked-up address with its cached transactions.
fn chain(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<ChainFact>> {
    let mut stmt = conn.prepare(
        "SELECT b.address, b.funded_sat, b.spent_sat, b.tx_count, h.first_seen, h.last_seen, h.data
         FROM balances b LEFT JOIN address_history h ON h.address = b.address ORDER BY b.address",
    )?;
    let rows = stmt.query_map([], |r| {
        let history: Option<AddressHistory> = r.get::<_, Option<String>>(6)?.and_then(|d| serde_json::from_str(&d).ok());
        let secs = |v: Option<i64>| v.and_then(Timestamp::from_unix_secs);
        Ok(ChainFact {
            address: r.get(0)?,
            funded_sat: r.get::<_, i64>(1)? as u64,
            spent_sat: r.get::<_, i64>(2)? as u64,
            tx_count: r.get::<_, i64>(3)? as u64,
            first_seen: secs(r.get(4)?),
            last_seen: secs(r.get(5)?),
            txs: history.map(|h| h.txs.into_iter().map(|t| TxFact { txid: t.txid, at: t.time }).collect()).unwrap_or_default(),
        })
    })?;
    rows.collect()
}
