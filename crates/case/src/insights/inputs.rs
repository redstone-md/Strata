//! What the lead engine reads from the case: key findings with their file times, and the
//! crypto-relevant slice of the timeline.

use crate::Case;
use strata_chain::addresses_in;
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Result, Timestamp};
use strata_leads::{EventRecord, KeyFinding};

/// Findings considered, most valuable first; beyond this the engine would only add noise.
const MAX_FINDINGS: usize = 50_000;
/// Event kinds that matter even without a crypto tag (accounts, downloads, installs, mail).
const ACCOUNT_KINDS: &str = "'AccountSeen','Login','Download','ProgramInstalled','Email','FormInput'";

fn category(name: &str) -> HitCategory {
    serde_json::from_value(serde_json::Value::String(name.to_string())).unwrap_or(HitCategory::Marker)
}

impl Case {
    /// Keys, seeds, wallets (and addresses that have an on-chain history) with the created /
    /// modified times of the file they were found in.
    pub fn key_findings(&self, min_confidence: f32) -> Result<Vec<KeyFinding>> {
        let sql = format!(
            "SELECT h.id, h.evidence_id, h.category, h.label, h.value, h.details, h.file_path, h.file_state,
                    MIN(f.created), MAX(f.modified)
             FROM hits h LEFT JOIN files f INDEXED BY files_path
               ON f.evidence_id = h.evidence_id AND f.volume_idx = h.volume_idx AND f.path = h.file_path
             WHERE h.confidence >= ?1
               AND (h.category IN ('PrivateKey','ExtendedKey','Mnemonic','Wallet')
                    OR (h.category = 'Address' AND h.value IN (SELECT address FROM address_history)))
             GROUP BY h.id
             ORDER BY CASE h.category WHEN 'Address' THEN 1 ELSE 0 END, h.confidence DESC, h.id
             LIMIT {MAX_FINDINGS}"
        );
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([min_confidence], |r| {
                let cat = category(&r.get::<_, String>(2)?);
                let value: String = r.get(4)?;
                let details: String = r.get(5)?;
                let mut addresses = Vec::new();
                if cat == HitCategory::Address {
                    addresses.push(value.clone());
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&details) {
                    addresses_in(&v, &mut addresses);
                }
                addresses.sort();
                addresses.dedup();
                let secs = |i: usize| r.get::<_, Option<i64>>(i).map(|v| v.and_then(Timestamp::from_unix_secs));
                let state: Option<String> = r.get(7)?;
                Ok(KeyFinding {
                    hit_id: r.get(0)?,
                    evidence: EvidenceId::new(r.get(1)?),
                    category: cat,
                    label: r.get(3)?,
                    value,
                    file_path: r.get(6)?,
                    deleted: state.is_some_and(|s| s != "Allocated"),
                    file_created: secs(8)?,
                    file_modified: secs(9)?,
                    addresses,
                })
            })?;
            rows.collect()
        })
    }

    /// Events by row id (what a lead points at), oldest first.
    pub fn events_by_id(&self, ids: &[i64]) -> Result<Vec<EventRecord>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let list: Vec<String> = ids.iter().map(i64::to_string).collect();
        self.event_records(&format!("SELECT id, evidence_id, data FROM events WHERE id IN ({}) ORDER BY at, id", list.join(",")))
    }

    fn event_records(&self, sql: &str) -> Result<Vec<EventRecord>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, u32>(1)?, r.get::<_, String>(2)?)))?;
            Ok(rows
                .filter_map(|r| r.ok())
                .filter_map(|(id, ev, data)| Some(EventRecord { id, evidence: EvidenceId::new(ev), event: serde_json::from_str(&data).ok()? }))
                .collect())
        })
    }

    /// Non-filesystem events that are crypto-tagged or about accounts, downloads and mail,
    /// oldest first.
    pub fn lead_events(&self, limit: usize) -> Result<Vec<EventRecord>> {
        let sql = format!(
            "SELECT id, evidence_id, data FROM events
             WHERE artifact NOT LIKE 'fs.%' AND (crypto = 1 OR kind IN ({ACCOUNT_KINDS}))
             ORDER BY at, id LIMIT {limit}"
        );
        self.event_records(&sql)
    }
}
