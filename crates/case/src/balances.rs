//! Address balances found for recovered keys and addresses.

use crate::Case;
use rusqlite::params;
use strata_chain::{AddressBalance, addresses_in};
use strata_kernel::Result;

impl Case {
    /// Distinct addresses mentioned by findings (address hits and addresses derived from keys)
    /// that have not been looked up yet.
    pub fn unchecked_addresses(&self) -> Result<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT category, value, details FROM hits
                 WHERE category IN ('Address','PrivateKey','ExtendedKey','Mnemonic','Wallet')",
            )?;
            let mut out: Vec<String> = Vec::new();
            let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
            for row in rows {
                let (category, value, details) = row?;
                if category == "Address" {
                    out.push(value);
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&details) {
                    addresses_in(&v, &mut out);
                }
            }
            out.sort();
            out.dedup();
            let mut known = conn.prepare("SELECT 1 FROM balances WHERE address = ?1")?;
            Ok(out.into_iter().filter(|a| !known.exists([a]).unwrap_or(false)).collect())
        })
    }

    pub fn store_balance(&self, b: &AddressBalance) -> Result<()> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO balances (address, funded_sat, spent_sat, tx_count, mempool_delta_sat, source, checked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![b.address, b.funded_sat as i64, b.spent_sat as i64, b.tx_count as i64, b.mempool_delta_sat, b.source, now],
            )
            .map(|_| ())
        })
    }

    /// Looked-up addresses, used ones first, richest first.
    pub fn balances(&self) -> Result<Vec<AddressBalance>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT address, funded_sat, spent_sat, tx_count, mempool_delta_sat, source FROM balances
                 ORDER BY (funded_sat - spent_sat) DESC, tx_count DESC",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(AddressBalance {
                    address: r.get(0)?,
                    funded_sat: r.get::<_, i64>(1)? as u64,
                    spent_sat: r.get::<_, i64>(2)? as u64,
                    tx_count: r.get::<_, i64>(3)? as u64,
                    mempool_delta_sat: r.get(4)?,
                    source: r.get(5)?,
                })
            })?;
            rows.collect()
        })
    }

    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        self.with_conn(|conn| conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.with_conn(|conn| conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)", [key, value]).map(|_| ()))
    }
}
