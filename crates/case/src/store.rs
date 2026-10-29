//! Hit persistence and queries.

use crate::Attribution;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use strata_kernel::EvidenceId;
use strata_kernel::scan::{Hit, HitCategory};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHit {
    pub id: i64,
    pub evidence: EvidenceId,
    pub hit: Hit,
    pub volume: Option<u32>,
    pub file_path: Option<String>,
    pub file_state: Option<String>,
    pub file_offset: Option<u64>,
    /// Places this value was found (1 unless the query grouped by value).
    #[serde(default = "one")]
    pub occurrences: u64,
    /// Disks the value was found on (just `evidence` unless grouped).
    #[serde(default)]
    pub disks: Vec<EvidenceId>,
}

fn one() -> u64 {
    1
}

#[derive(Debug, Clone, Default)]
pub struct HitQuery {
    pub evidence: Option<EvidenceId>,
    pub categories: Vec<HitCategory>,
    pub min_confidence: f32,
    pub text: Option<String>,
    pub limit: usize,
    pub offset: usize,
    /// One row per distinct value (best-confidence occurrence), with occurrence counts.
    /// File-level findings (wallet files, carved/renamed files) are never merged.
    pub group_by_value: bool,
    /// Only this exact value (lists every place a grouped value was found).
    pub exact_value: Option<String>,
    /// Only these hit ids (findings a lead points at).
    pub ids: Vec<i64>,
    /// Hide findings whose file is dated and was neither created nor modified in the period.
    /// Findings outside files (free space) and in undated files are kept.
    pub period: Option<strata_kernel::Period>,
}

/// SQL condition for [`HitQuery::period`] (bounds are numbers, inlined).
fn period_condition(p: &strata_kernel::Period) -> String {
    let from = p.from.map_or(i64::MIN, |t| t.unix_secs());
    let to = p.to.map_or(i64::MAX, |t| t.unix_secs());
    // Looked up by path: the (disk, volume) key prefix would scan a whole volume per finding.
    let files = "FROM files f INDEXED BY files_path WHERE f.evidence_id = hits.evidence_id AND f.path = hits.file_path";
    format!(
        " AND (file_path IS NULL
           OR EXISTS (SELECT 1 {files} AND ((f.created >= {from} AND f.created < {to}) OR (f.modified >= {from} AND f.modified < {to})))
           OR NOT EXISTS (SELECT 1 {files} AND (f.created IS NOT NULL OR f.modified IS NOT NULL)))"
    )
}

/// Grouping key: equal values merge, except findings that describe one specific file.
const GROUP_KEY: &str = "CASE WHEN detector LIKE 'wallet.%' OR detector LIKE 'carve.%' OR detector LIKE 'identify.%'      THEN 'id:' || id ELSE category || '|' || value END";

pub(crate) fn category_name(c: HitCategory) -> String {
    format!("{c:?}")
}

pub(crate) fn category_from(name: &str) -> HitCategory {
    serde_json::from_value(serde_json::Value::String(name.to_string())).unwrap_or(HitCategory::Marker)
}

/// Insert inside the caller's transaction.
pub(crate) fn insert(conn: &Connection, evidence: EvidenceId, hits: &[(Hit, Attribution)]) -> rusqlite::Result<usize> {
    let mut inserted = 0;
    {
        let mut stmt = conn.prepare_cached(
            "INSERT OR IGNORE INTO hits (evidence_id, detector, category, offset, len, confidence, label, value,
             details, volume_idx, file_path, file_state, file_offset)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?;
        for (h, a) in hits {
            inserted += stmt.execute(params![
                evidence.get(),
                h.detector,
                category_name(h.category),
                h.offset as i64,
                h.len,
                h.confidence.get(),
                h.label,
                h.value,
                h.details.to_string(),
                a.volume,
                a.file.as_ref().map(|f| f.path.clone()),
                a.file.as_ref().map(|f| format!("{:?}", f.state)),
                a.file.as_ref().map(|f| f.file_offset as i64),
            ])?;
        }
    }
    Ok(inserted)
}

/// Add copies dropped by the repetition cap to the stored copy they follow.
pub(crate) fn add_repeats(conn: &Connection, evidence: EvidenceId, overflow: &[crate::repeats::Overflow]) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare_cached(
        "UPDATE hits SET repeats = repeats + ?4 WHERE evidence_id = ?1 AND detector = ?2 AND offset = ?3 AND value = ?5",
    )?;
    for o in overflow {
        stmt.execute(params![evidence.get(), o.detector, o.offset as i64, o.extra as i64, o.value])?;
    }
    Ok(())
}

pub(crate) fn query(conn: &Connection, q: &HitQuery) -> rusqlite::Result<Vec<StoredHit>> {
    // With GROUP BY, SQLite takes the bare columns from the row holding MAX(confidence).
    let (aggregates, grouping) = if q.group_by_value {
        ("MAX(confidence), COUNT(*) + SUM(repeats), GROUP_CONCAT(DISTINCT evidence_id)", format!(" GROUP BY {GROUP_KEY}"))
    } else {
        ("confidence, 1 + repeats, evidence_id", String::new())
    };
    let mut sql = format!(
        "SELECT id, evidence_id, detector, category, offset, len, {aggregates}, label, value, details,
                volume_idx, file_path, file_state, file_offset FROM hits WHERE confidence >= ?1"
    );
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(q.min_confidence)];
    if let Some(e) = q.evidence {
        args.push(Box::new(e.get()));
        sql += &format!(" AND evidence_id = ?{}", args.len());
    }
    if !q.categories.is_empty() {
        let list: Vec<String> = q.categories.iter().map(|c| format!("'{}'", category_name(*c))).collect();
        sql += &format!(" AND category IN ({})", list.join(","));
    }
    if let Some(t) = q.text.as_ref().filter(|t| !t.is_empty()) {
        args.push(Box::new(format!("%{t}%")));
        let n = args.len();
        sql += &format!(" AND (value LIKE ?{n} OR label LIKE ?{n} OR file_path LIKE ?{n})");
    }
    if let Some(v) = &q.exact_value {
        args.push(Box::new(v.clone()));
        sql += &format!(" AND value = ?{}", args.len());
    }
    if let Some(p) = q.period.filter(|p| !p.is_all()) {
        sql += &period_condition(&p);
    }
    if !q.ids.is_empty() {
        let ids: Vec<String> = q.ids.iter().map(i64::to_string).collect();
        sql += &format!(" AND id IN ({})", ids.join(","));
    }
    sql += &grouping;
    sql += if q.group_by_value { " ORDER BY 7 DESC, 8 DESC, value" } else { " ORDER BY confidence DESC, evidence_id, offset" };
    if q.limit > 0 {
        sql += &format!(" LIMIT {} OFFSET {}", q.limit, q.offset);
    }
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter().map(|a| a.as_ref())), |r| {
        let details: String = r.get(11)?;
        let mut hit = Hit::new(&r.get::<_, String>(2)?, category_from(&r.get::<_, String>(3)?), r.get::<_, i64>(4)? as u64, r.get::<_, u32>(5)? as usize)
            .confidence(strata_kernel::Confidence::new(r.get(6)?))
            .label(r.get::<_, String>(9)?)
            .value(r.get::<_, String>(10)?);
        hit.details = serde_json::from_str(&details).unwrap_or_default();
        let disks: String = r.get::<_, rusqlite::types::Value>(8).map(|v| match v {
            rusqlite::types::Value::Integer(i) => i.to_string(),
            rusqlite::types::Value::Text(t) => t,
            _ => String::new(),
        })?;
        Ok(StoredHit {
            id: r.get(0)?,
            evidence: EvidenceId::new(r.get(1)?),
            hit,
            volume: r.get(12)?,
            file_path: r.get(13)?,
            file_state: r.get(14)?,
            file_offset: r.get::<_, Option<i64>>(15)?.map(|v| v as u64),
            occurrences: r.get::<_, i64>(7)? as u64,
            disks: disks.split(',').filter_map(|d| d.parse().ok()).map(EvidenceId::new).collect(),
        })
    })?;
    rows.collect()
}

/// Distinct findings per category, counted the way the lists group them (one per value, or
/// per row for wallet files, carved files and renamed-extension alerts).
pub(crate) fn counts(conn: &Connection, evidence: Option<EvidenceId>, min_confidence: f32) -> rusqlite::Result<Vec<(HitCategory, u64)>> {
    let sql = format!(
        "SELECT category, COUNT(DISTINCT {GROUP_KEY}) FROM hits WHERE (?1 IS NULL OR evidence_id = ?1) AND confidence >= ?2
         GROUP BY category ORDER BY 2 DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![evidence.map(|e| e.get()), min_confidence], |r| Ok((category_from(&r.get::<_, String>(0)?), r.get::<_, i64>(1)? as u64)))?;
    rows.collect()
}

#[cfg(test)]
mod period_tests {
    use crate::{Attribution, Case, FileRef, HitQuery};
    use strata_fs::EntryState;
    use strata_kernel::scan::{Hit, HitCategory};
    use strata_kernel::{Period, Timestamp};

    #[test]
    fn period_hides_findings_in_files_dated_outside_it() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("zero.img");
        std::fs::write(&img, vec![0u8; 1 << 20]).unwrap();
        let case = Case::open(&dir.path().join("t.strata")).unwrap();
        let id = case.add_evidence(&img.display().to_string()).unwrap().id;
        let in_file = |path: &str, value: &str, offset: u64| {
            let file = FileRef { path: path.into(), state: EntryState::Allocated, file_offset: 0 };
            (Hit::new("crypto.wif", HitCategory::PrivateKey, offset, 51).value(value), Attribution { volume: Some(0), file: Some(file) })
        };
        let free = (Hit::new("crypto.wif", HitCategory::PrivateKey, 900, 51).value("free"), Attribution::default());
        case.store_hits(id, &[in_file("old.txt", "old", 100), in_file("new.txt", "new", 200), in_file("undated.txt", "undated", 300), free]).unwrap();
        let secs = |y| Timestamp::from_civil(y, 6, 1, 0, 0, 0).unwrap().unix_secs();
        case.with_write(|c| {
            c.execute(
                "INSERT INTO files (evidence_id, volume_idx, file_idx, path, name, size, is_dir, state, created, modified) VALUES
                 (?1, 0, 1, 'old.txt', 'old.txt', 1, 0, 'Allocated', ?2, ?2),
                 (?1, 0, 2, 'new.txt', 'new.txt', 1, 0, 'Allocated', ?3, ?3),
                 (?1, 0, 3, 'undated.txt', 'undated.txt', 1, 0, 'Allocated', NULL, NULL)",
                rusqlite::params![id.get(), secs(2010), secs(2018)],
            )
        })
        .unwrap();
        let values = |period| {
            let mut v: Vec<String> = case.hits(&HitQuery { period, ..HitQuery::default() }).unwrap().into_iter().map(|h| h.hit.value).collect();
            v.sort();
            v
        };
        assert_eq!(values(None).len(), 4);
        assert_eq!(values(Period::parse("2008", "2013")), ["free", "old", "undated"]);
    }
}

#[cfg(test)]
mod promote_tests {
    use crate::{Attribution, Case, FileRef, HitQuery};
    use strata_fs::EntryState;
    use strata_kernel::scan::{Hit, HitCategory};
    use strata_kernel::{Confidence, EvidenceId};

    fn key(case: &Case, id: EvidenceId, path: &str, offset: u64) {
        let file = FileRef { path: path.into(), state: EntryState::Allocated, file_offset: 0 };
        let hit = Hit::new("crypto.hex_key", HitCategory::PrivateKey, offset, 64).value(path).confidence(Confidence::new(0.15));
        case.store_hits(id, &[(hit, Attribution { volume: Some(0), file: Some(file) })]).unwrap();
    }

    #[test]
    fn files_named_like_key_backups_lift_their_findings() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("zero.img");
        std::fs::write(&img, vec![0u8; 1 << 20]).unwrap();
        let case = Case::open(&dir.path().join("t.strata")).unwrap();
        let id = case.add_evidence(&img.display().to_string()).unwrap().id;
        key(&case, id, "home/u/Desktop/btc privkey.txt", 1);
        key(&case, id, "home/u/notes/todo.txt", 2);
        key(&case, id, "home/u/node_modules/wallet/index.js", 3);
        assert_eq!(case.promote_wallet_named_files(id, 0.4).unwrap(), 1);
        let shown: Vec<String> = case.hits(&HitQuery { min_confidence: 0.4, ..HitQuery::default() }).unwrap().into_iter().map(|h| h.hit.value).collect();
        assert_eq!(shown, ["home/u/Desktop/btc privkey.txt"]);
        assert_eq!(case.promote_wallet_named_files(id, 0.4).unwrap(), 0, "idempotent");
    }
}
