//! Stored raw-scan findings re-read for a fresh verdict when detector rules improve (see the
//! workbench `Recheck` step). File-level findings (wallet files, archive members) are left out:
//! their offsets do not point into the disk.

use crate::case::db;
use crate::{Case, CaseWriter};
use rusqlite::params;
use strata_kernel::{EvidenceId, Result};

/// One stored finding to re-check.
pub struct RecheckRow {
    pub id: i64,
    pub detector: String,
    pub offset: u64,
    pub len: usize,
    pub value: String,
}

/// What the detector says now: its confidence and details, or `None` when it no longer
/// reports the finding.
pub type Verdict = Option<(f32, serde_json::Value)>;

const RAW_SCAN: &str = "evidence_id = ?1 AND (file_path IS NULL OR file_path NOT LIKE '%!/%')";

fn detector_list(detectors: &[&str]) -> String {
    detectors.iter().map(|d| format!("'{d}'")).collect::<Vec<_>>().join(",")
}

impl Case {
    pub fn recheck_count(&self, id: EvidenceId, detectors: &[&str]) -> Result<u64> {
        let sql = format!("SELECT COUNT(*) FROM hits WHERE {RAW_SCAN} AND detector IN ({})", detector_list(detectors));
        self.with_conn(|c| c.query_row(&sql, [id.get()], |r| r.get::<_, i64>(0))).map(|n| n as u64)
    }

    /// The next `limit` findings after row `after`, in row order.
    pub fn recheck_rows(&self, id: EvidenceId, detectors: &[&str], after: i64, limit: usize) -> Result<Vec<RecheckRow>> {
        let sql = format!(
            "SELECT id, detector, offset, len, value FROM hits WHERE {RAW_SCAN} AND detector IN ({}) AND id > ?2
             ORDER BY id LIMIT ?3",
            detector_list(detectors)
        );
        self.with_conn(|c| {
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt.query_map(params![id.get(), after, limit as i64], |r| {
                Ok(RecheckRow {
                    id: r.get(0)?,
                    detector: r.get(1)?,
                    offset: r.get::<_, i64>(2)? as u64,
                    len: r.get::<_, i64>(3)? as usize,
                    value: r.get(4)?,
                })
            })?;
            rows.collect()
        })
    }
}

impl CaseWriter<'_> {
    /// Apply verdicts: findings no longer reported are removed, the rest take the new
    /// confidence and details. Returns `(removed, changed)`.
    pub fn rechecked(&self, verdicts: &[(i64, Verdict)]) -> Result<(usize, usize)> {
        let (mut removed, mut changed) = (0, 0);
        for (id, verdict) in verdicts {
            match verdict {
                None => removed += self.tx().execute("DELETE FROM hits WHERE id = ?1", [id]).map_err(db)?,
                Some((confidence, details)) => {
                    changed += self
                        .tx()
                        .execute(
                            "UPDATE hits SET confidence = ?2, details = ?3 WHERE id = ?1 AND (confidence <> ?2 OR details <> ?3)",
                            params![id, confidence, details.to_string()],
                        )
                        .map_err(db)?
                }
            }
        }
        Ok((removed, changed))
    }
}
