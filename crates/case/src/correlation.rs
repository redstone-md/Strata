//! Cross-evidence correlation: what several disks have in common and where one fills the
//! other's gaps.

use crate::Case;
use crate::store::category_name;
use serde::{Deserialize, Serialize};
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Result};
use strata_source::CompositeSource;

/// The same key, address, identity or URL found on more than one disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFinding {
    pub category: HitCategory,
    pub value: String,
    pub evidence: Vec<EvidenceId>,
    pub occurrences: u64,
}

/// The same path present on several disks in different states — e.g. deleted and
/// overwritten on one, intact on the other.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileComplement {
    pub path: String,
    /// `(evidence, state, size)` per disk that has the path.
    pub copies: Vec<(EvidenceId, String, u64)>,
}

/// Two evidence items that are images of the same physical medium.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SameMedium {
    pub primary: EvidenceId,
    pub other: EvidenceId,
    /// Bytes unreadable in `primary` that `other` provides.
    pub recoverable_bytes: u64,
}

pub struct CorrelationService<'a> {
    case: &'a Case,
}

impl<'a> CorrelationService<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    pub fn shared_findings(&self, categories: &[HitCategory]) -> Result<Vec<SharedFinding>> {
        let list: Vec<String> = categories.iter().map(|c| format!("'{}'", category_name(*c))).collect();
        let sql = format!(
            "SELECT category, value, GROUP_CONCAT(DISTINCT evidence_id), COUNT(*) + SUM(repeats) FROM hits
             WHERE category IN ({}) AND value <> ''
             GROUP BY category, value HAVING COUNT(DISTINCT evidence_id) > 1
             ORDER BY COUNT(DISTINCT evidence_id) DESC, COUNT(*) DESC LIMIT 5000",
            list.join(",")
        );
        self.case.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], |r| {
                let cat: String = r.get(0)?;
                let ev: String = r.get(2)?;
                Ok(SharedFinding {
                    category: serde_json::from_value(serde_json::Value::String(cat)).unwrap_or(HitCategory::Marker),
                    value: r.get(1)?,
                    evidence: ev.split(',').filter_map(|s| s.parse().ok()).map(EvidenceId::new).collect(),
                    occurrences: r.get::<_, i64>(3)? as u64,
                })
            })?;
            rows.collect()
        })
    }

    /// Pairs of evidence that image the same disk; their bad sectors can fill each other.
    pub fn same_media(&self) -> Result<Vec<SameMedium>> {
        let ids: Vec<EvidenceId> = self.case.evidence()?.into_iter().map(|e| e.id).collect();
        let mut out = Vec::new();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                let (sa, sb) = (self.case.source(*a)?, self.case.source(*b)?);
                if CompositeSource::same_medium(sa.as_ref(), sb.as_ref(), 8) {
                    let ab = CompositeSource::new(vec![sa.clone(), sb.clone()]).recovered_bytes();
                    let ba = CompositeSource::new(vec![sb, sa]).recovered_bytes();
                    out.push(SameMedium { primary: *a, other: *b, recoverable_bytes: ab });
                    out.push(SameMedium { primary: *b, other: *a, recoverable_bytes: ba });
                }
            }
        }
        Ok(out)
    }

    /// Paths (non-system files) that exist on several disks with differing state or size.
    pub fn file_complements(&self) -> Result<Vec<FileComplement>> {
        self.case.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, GROUP_CONCAT(evidence_id || '|' || state || '|' || size, ';') FROM files
                 WHERE is_dir = 0 AND path NOT LIKE '$%'
                 GROUP BY lower(path)
                 HAVING COUNT(DISTINCT evidence_id) > 1 AND (COUNT(DISTINCT state) > 1 OR COUNT(DISTINCT size) > 1)
                 LIMIT 5000",
            )?;
            let rows = stmt.query_map([], |r| {
                let copies: String = r.get(1)?;
                Ok(FileComplement {
                    path: r.get(0)?,
                    copies: copies
                        .split(';')
                        .filter_map(|c| {
                            let mut p = c.split('|');
                            Some((EvidenceId::new(p.next()?.parse().ok()?), p.next()?.to_string(), p.next()?.parse().ok()?))
                        })
                        .collect(),
                })
            })?;
            rows.collect()
        })
    }
}
