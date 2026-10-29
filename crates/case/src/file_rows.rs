//! Queries over the stored file listing (`files` table): name search across every entry,
//! deleted and orphaned ones included, and the content types the classify step recorded.

use crate::Case;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strata_kernel::{EvidenceId, Result};

/// One stored file entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileRow {
    pub evidence: EvidenceId,
    pub volume: u32,
    pub file_idx: usize,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    /// `Allocated`, `Deleted`, `Orphan`.
    pub state: String,
    /// Unix seconds.
    pub modified: Option<i64>,
    pub detected_type: Option<String>,
    pub extension_mismatch: bool,
}

/// Content type and renamed-extension flag per `(volume, file index)`.
pub type FileTypes = HashMap<(u32, usize), (String, bool)>;

/// SQL condition for a name pattern: `*`/`?` make it a glob over the whole name, otherwise
/// it matches anywhere in the name. ASCII letters match in any case.
fn name_condition(pattern: &str) -> (String, String) {
    if pattern.contains(['*', '?']) {
        ("lower(name) GLOB ?1".into(), pattern.to_lowercase())
    } else {
        let escaped = pattern.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        ("name LIKE ?1 ESCAPE '\\'".into(), format!("%{escaped}%"))
    }
}

impl Case {
    /// Entries whose name matches `pattern` (see [`name_condition`]) on every disk or one,
    /// deleted and orphaned ones included, at most `limit`.
    pub fn find_files_by_name(&self, pattern: &str, evidence: Option<EvidenceId>, limit: usize) -> Result<Vec<FileRow>> {
        let (condition, value) = name_condition(pattern.trim());
        let sql = format!(
            "SELECT evidence_id, volume_idx, file_idx, path, name, size, is_dir, state, modified, detected_type, extension_mismatch
             FROM files WHERE {condition} AND (?2 IS NULL OR evidence_id = ?2)
             ORDER BY state = 'Allocated', evidence_id, path LIMIT ?3"
        );
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params![value, evidence.map(|e| e.get()), limit.max(1) as i64], |r| {
                Ok(FileRow {
                    evidence: EvidenceId::new(r.get(0)?),
                    volume: r.get(1)?,
                    file_idx: r.get::<_, i64>(2)? as usize,
                    path: r.get(3)?,
                    name: r.get(4)?,
                    size: r.get::<_, i64>(5)? as u64,
                    is_dir: r.get(6)?,
                    state: r.get(7)?,
                    modified: r.get(8)?,
                    detected_type: r.get(9)?,
                    extension_mismatch: r.get(10)?,
                })
            })?;
            rows.collect()
        })
    }

    /// Whether one disk has a stored file listing (the index step ran).
    pub fn has_files(&self, id: EvidenceId) -> Result<bool> {
        self.with_conn(|conn| conn.query_row("SELECT EXISTS (SELECT 1 FROM files WHERE evidence_id = ?1)", [id.get()], |r| r.get(0)))
    }

    /// Content types recorded for one disk by the classify step.
    pub fn file_types(&self, id: EvidenceId) -> Result<FileTypes> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT volume_idx, file_idx, detected_type, extension_mismatch FROM files
                 WHERE evidence_id = ?1 AND detected_type IS NOT NULL",
            )?;
            let rows = stmt.query_map([id.get()], |r| {
                Ok(((r.get::<_, u32>(0)?, r.get::<_, i64>(1)? as usize), (r.get::<_, String>(2)?, r.get::<_, bool>(3)?)))
            })?;
            rows.collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::name_condition;

    #[test]
    fn patterns() {
        assert_eq!(name_condition("*.DAT"), ("lower(name) GLOB ?1".into(), "*.dat".into()));
        assert_eq!(name_condition("50%_off").1, "%50\\%\\_off%");
    }
}
