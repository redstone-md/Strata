//! Findings for the connection graph: every key, seed and wallet above the noise floor, what
//! else sits in their files, identities read from artefacts, the places of addresses used on
//! chain, and how widely candidate identities are spread over the case.

use crate::store::category_from;
use rusqlite::{Connection, Row, params_from_iter};
use std::collections::{BTreeSet, HashMap};
use strata_chain::addresses_in;
use strata_graph::{FindingFact, Limits, SpreadFact};
use strata_kernel::{EvidenceId, Timestamp};

const COLUMNS: &str = "h.id, h.evidence_id, h.category, h.detector, h.label, h.value, h.confidence, h.details, h.file_path, h.file_state";

fn finding(r: &Row<'_>, times: Option<(Option<i64>, Option<i64>)>) -> rusqlite::Result<FindingFact> {
    let details: serde_json::Value = serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default();
    let mut addresses = Vec::new();
    addresses_in(&details, &mut addresses);
    addresses.sort();
    addresses.dedup();
    let state: Option<String> = r.get(9)?;
    let (created, modified) = times.unwrap_or_default();
    Ok(FindingFact {
        hit: r.get(0)?,
        disk: EvidenceId::new(r.get(1)?),
        category: category_from(&r.get::<_, String>(2)?),
        detector: r.get(3)?,
        label: r.get(4)?,
        value: r.get(5)?,
        confidence: r.get(6)?,
        detail: details.get("detail").and_then(|d| d.as_str()).filter(|d| !d.is_empty()).map(str::to_string),
        file: r.get(8)?,
        deleted: state.is_some_and(|s| s != "Allocated"),
        file_times: (created.and_then(Timestamp::from_unix_secs), modified.and_then(Timestamp::from_unix_secs)),
        addresses,
    })
}

/// Keys, seeds and wallets, most confident first, with the times of their files.
pub(super) fn secrets(conn: &Connection, limits: &Limits) -> rusqlite::Result<Vec<FindingFact>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS}, MIN(f.created), MAX(f.modified)
         FROM hits h LEFT JOIN files f
           ON f.evidence_id = h.evidence_id AND f.volume_idx = h.volume_idx AND f.path = h.file_path
         WHERE h.category IN ('PrivateKey','ExtendedKey','Mnemonic','Wallet') AND h.confidence >= ?1
         GROUP BY h.id ORDER BY h.confidence DESC, h.id LIMIT ?2"
    ))?;
    let rows = stmt.query_map(rusqlite::params![limits.min_confidence, limits.secrets as i64], |r| finding(r, Some((r.get(10)?, r.get(11)?))))?;
    rows.collect()
}

/// Identities and addresses inside the files that hold secrets, plus identities read from
/// artefacts (saved logins, mail settings, miner configs) wherever they are. One pass over the
/// identity and address rows.
pub(super) fn beside(conn: &Connection, secrets: &[FindingFact], limits: &Limits) -> rusqlite::Result<Vec<FindingFact>> {
    let mut files: BTreeSet<(EvidenceId, &str)> = BTreeSet::new();
    for s in secrets {
        if let Some(path) = &s.file
            && files.len() < limits.secret_files
        {
            files.insert((s.disk, path.as_str()));
        }
    }
    let paths: BTreeSet<&str> = files.iter().map(|f| f.1).collect();
    let marks = vec!["?"; paths.len()].join(",");
    let in_files = if paths.is_empty() { "0".to_string() } else { format!("h.file_path IN ({marks})") };
    let sql = format!(
        "SELECT {COLUMNS} FROM hits h
         WHERE h.category IN ('Identity','Address') AND h.confidence >= {floor}
           AND ({in_files} OR h.detector = 'artifacts.identity')
         ORDER BY h.id LIMIT {limit}",
        floor = limits.min_confidence,
        limit = limits.placements
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(paths.iter()), |r| finding(r, None))?;
    let mut out = Vec::new();
    for f in rows {
        let f = f?;
        let in_secret_file = f.file.as_deref().is_some_and(|p| files.contains(&(f.disk, p)));
        if in_secret_file || f.detector == "artifacts.identity" {
            out.push(f);
        }
    }
    Ok(out)
}

/// Where addresses with an on-chain history were found.
pub(super) fn used_addresses(conn: &Connection, limits: &Limits) -> rusqlite::Result<Vec<FindingFact>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM hits h
         WHERE h.category = 'Address' AND h.confidence >= ?1
           AND h.value IN (SELECT address FROM balances WHERE tx_count > 0 OR funded_sat > 0)
         ORDER BY h.id LIMIT ?2"
    ))?;
    let rows = stmt.query_map(rusqlite::params![limits.min_confidence, limits.placements as i64], |r| finding(r, None))?;
    rows.collect()
}

/// Copies, files, disks and a sample of places of each identity value.
pub(super) fn spreads(conn: &Connection, values: &[String], limits: &Limits) -> rusqlite::Result<Vec<SpreadFact>> {
    let mut out: HashMap<String, SpreadFact> = HashMap::new();
    for chunk in values.chunks(500) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare(&format!(
            "SELECT value, COUNT(*) + SUM(repeats), COUNT(DISTINCT file_path), GROUP_CONCAT(DISTINCT evidence_id)
             FROM hits WHERE category = 'Identity' AND value IN ({marks}) GROUP BY value"
        ))?;
        let rows = stmt.query_map(params_from_iter(chunk.iter()), |r| {
            let disks: String = r.get::<_, Option<String>>(3)?.unwrap_or_default();
            Ok(SpreadFact {
                value: r.get(0)?,
                copies: r.get::<_, i64>(1)? as u64,
                files: r.get::<_, i64>(2)? as u64,
                disks: disks.split(',').filter_map(|d| d.parse().ok()).map(EvidenceId::new).collect(),
                sample_paths: Vec::new(),
            })
        })?;
        for s in rows {
            let s = s?;
            out.insert(s.value.clone(), s);
        }
        let mut stmt = conn.prepare(&format!(
            "SELECT value, file_path FROM (
                 SELECT value, file_path, ROW_NUMBER() OVER (PARTITION BY value ORDER BY first) AS rn
                 FROM (SELECT value, file_path, MIN(id) AS first FROM hits
                       WHERE category = 'Identity' AND value IN ({marks}) AND file_path IS NOT NULL
                       GROUP BY value, file_path))
             WHERE rn <= {}",
            limits.spread_paths
        ))?;
        let rows = stmt.query_map(params_from_iter(chunk.iter()), |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (value, path) = row?;
            if let Some(s) = out.get_mut(&value) {
                s.sample_paths.push(path);
            }
        }
    }
    let mut spreads: Vec<SpreadFact> = out.into_values().collect();
    spreads.sort_by(|a, b| a.value.cmp(&b.value));
    Ok(spreads)
}
