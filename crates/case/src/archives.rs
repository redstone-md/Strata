//! Members unpacked from archives found on evidence (`archive_members` table) and the file
//! selection the unpack step starts from.

use crate::Case;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use strata_kernel::{EvidenceId, Result};

/// One member of an archive (at any nesting level).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchiveMemberRow {
    /// Path of the archive file on the evidence (or a carved-file label).
    pub archive_path: String,
    /// `archive!/dir/inner.rar!/file.txt`
    pub member_path: String,
    pub depth: u32,
    pub size: Option<u64>,
    pub packed: Option<u64>,
    /// Bytes actually recovered.
    pub recovered: u64,
    pub encrypted: bool,
    pub detected_type: Option<String>,
    pub extension_mismatch: bool,
    /// Unix seconds.
    pub modified: Option<i64>,
    /// JSON array of damage notes.
    pub damage: String,
}

impl Case {
    /// Files whose content type (from the classify step) is one of `types`, as
    /// `(volume, file index, type)`. `None` when the evidence was never classified.
    pub fn files_of_types(&self, id: EvidenceId, types: &[&str]) -> Result<Option<Vec<(u32, usize, String)>>> {
        self.with_conn(|conn| {
            let classified: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM files WHERE evidence_id = ?1 AND detected_type IS NOT NULL)",
                [id.get()],
                |r| r.get(0),
            )?;
            if !classified {
                return Ok(None);
            }
            let mut stmt = conn.prepare(
                "SELECT volume_idx, file_idx, detected_type FROM files
                 WHERE evidence_id = ?1 AND is_dir = 0 AND detected_type IS NOT NULL",
            )?;
            let rows = stmt.query_map([id.get()], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, i64>(1)? as usize, r.get::<_, String>(2)?)))?;
            let mut out = Vec::new();
            for row in rows {
                let (vol, idx, ty) = row?;
                if types.contains(&ty.as_str()) {
                    out.push((vol, idx, ty));
                }
            }
            Ok(Some(out))
        })
    }

    pub fn archive_members(&self, id: EvidenceId) -> Result<Vec<ArchiveMemberRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT archive_path, member_path, depth, size, packed, recovered, encrypted, detected_type,
                        extension_mismatch, modified, damage
                 FROM archive_members WHERE evidence_id = ?1 ORDER BY member_path",
            )?;
            let rows = stmt.query_map([id.get()], |r| {
                Ok(ArchiveMemberRow {
                    archive_path: r.get(0)?,
                    member_path: r.get(1)?,
                    depth: r.get(2)?,
                    size: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                    packed: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    recovered: r.get::<_, i64>(5)? as u64,
                    encrypted: r.get(6)?,
                    detected_type: r.get(7)?,
                    extension_mismatch: r.get(8)?,
                    modified: r.get(9)?,
                    damage: r.get(10)?,
                })
            })?;
            rows.collect()
        })
    }
}

pub(crate) fn insert_members(conn: &Connection, id: EvidenceId, rows: &[ArchiveMemberRow]) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare_cached(
        "INSERT OR REPLACE INTO archive_members (evidence_id, archive_path, member_path, depth, size, packed,
         recovered, encrypted, detected_type, extension_mismatch, modified, damage)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?;
    for m in rows {
        stmt.execute(params![
            id.get(),
            m.archive_path,
            m.member_path,
            m.depth,
            m.size.map(|v| v as i64),
            m.packed.map(|v| v as i64),
            m.recovered as i64,
            m.encrypted,
            m.detected_type,
            m.extension_mismatch,
            m.modified,
            m.damage
        ])?;
    }
    Ok(rows.len())
}
