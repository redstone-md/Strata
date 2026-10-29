//! Cached on-chain transaction histories of found addresses.

use super::json;
use crate::Case;
use rusqlite::{OptionalExtension, params};
use strata_chain::AddressHistory;
use strata_kernel::Result;

impl Case {
    pub fn store_history(&self, h: &AddressHistory) -> Result<()> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO address_history (address, first_seen, last_seen, tx_count, complete, data, checked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    h.address,
                    h.first_seen().map(|t| t.unix_secs()),
                    h.last_seen().map(|t| t.unix_secs()),
                    h.tx_count as i64,
                    h.complete,
                    json(h),
                    now
                ],
            )
            .map(|_| ())
        })
    }

    pub fn history_of(&self, address: &str) -> Result<Option<AddressHistory>> {
        self.with_conn(|conn| {
            let data: Option<String> = conn.query_row("SELECT data FROM address_history WHERE address = ?1", [address], |r| r.get(0)).optional()?;
            Ok(data.and_then(|d| serde_json::from_str(&d).ok()))
        })
    }

    /// Every cached history, oldest activity first.
    pub fn histories(&self) -> Result<Vec<AddressHistory>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT data FROM address_history ORDER BY first_seen, address")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            Ok(rows.filter_map(|r| r.ok()).filter_map(|d| serde_json::from_str(&d).ok()).collect())
        })
    }

    /// Addresses seen on chain (by the balance lookup) whose history is not cached yet.
    pub fn addresses_without_history(&self) -> Result<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT address FROM balances WHERE tx_count > 0
                 AND address NOT IN (SELECT address FROM address_history) ORDER BY address",
            )?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect()
        })
    }
}
