use crate::attribution::EvidenceLayout;
use crate::store::{self, HitQuery, StoredHit};
use crate::pool::ReadPool;
use crate::repeats::RepeatCap;
use crate::schema;
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use strata_engine::{ScanControl, ScanSummary, Scanner};
use strata_kernel::scan::HitCategory;
use strata_kernel::{ByteRange, Error, EvidenceId, Result};
use strata_source::{BlockSource, SourceInfo, open_source};
use strata_volume::{Volume, VolumeScanner};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub id: EvidenceId,
    pub info: SourceInfo,
    pub volumes: Vec<Volume>,
}

/// How often a scan saves its watermark when no hits force a commit.
pub const SAVE_EVERY: Duration = Duration::from_secs(3);

/// Hook run inside each scan commit with the saved watermark (see [`Case::scan_with`]).
pub type ScanCommit<'a> = &'a mut (dyn FnMut(&crate::CaseWriter<'_>, u64) -> Result<()> + Send);

pub(crate) fn db(e: rusqlite::Error) -> Error {
    Error::Other(format!("case database: {e}"))
}

fn parse_enum<T: serde::de::DeserializeOwned>(s: String) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(s)).ok()
}

pub(crate) fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// The aggregate root. Thread-safe: UI and background jobs share one `Arc<Case>`.
pub struct Case {
    root: PathBuf,
    conn: Mutex<Connection>,
    readers: ReadPool,
    sources: Mutex<HashMap<EvidenceId, Arc<dyn BlockSource>>>,
    layouts: Mutex<HashMap<EvidenceId, Arc<EvidenceLayout>>>,
}

impl Case {
    /// Open or create the case folder.
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root.join("cache"))?;
        let conn = Connection::open(root.join("case.db")).map_err(db)?;
        schema::apply(&conn).map_err(db)?;
        conn.busy_timeout(Duration::from_secs(30)).map_err(db)?;
        let readers = ReadPool::new(root.join("case.db"));
        Ok(Self { root: root.to_path_buf(), conn: Mutex::new(conn), readers, sources: Mutex::default(), layouts: Mutex::default() })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn name(&self) -> String {
        self.root.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
    }

    /// Register a disk image or physical drive and discover its volumes.
    pub fn add_evidence(&self, location: &str) -> Result<EvidenceRecord> {
        if let Some(existing) = self.evidence()?.into_iter().find(|e| e.info.location == location) {
            return Ok(existing);
        }
        let source = open_source(location, Some(&self.root.join("cache")))?;
        let info = source.info();
        let volumes = VolumeScanner::default().scan(source.as_ref());
        let id = {
            let mut conn = self.conn.lock();
            let tx = conn.transaction().map_err(db)?;
            tx.execute(
                "INSERT INTO evidence (label, location, kind, len, added_at, info) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![info.label, info.location, format!("{:?}", info.kind), info.len as i64, now(), serde_json::to_string(&info).unwrap_or_default()],
            )
            .map_err(db)?;
            let id = EvidenceId::new(tx.last_insert_rowid() as u32);
            for v in &volumes {
                tx.execute(
                    "INSERT INTO volumes (evidence_id, idx, start, len, fs, origin, label) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![id.get(), v.index, v.range.start() as i64, v.range.len() as i64, format!("{:?}", v.fs), format!("{:?}", v.origin), v.label],
                )
                .map_err(db)?;
            }
            tx.commit().map_err(db)?;
            id
        };
        self.sources.lock().insert(id, source);
        Ok(EvidenceRecord { id, info, volumes })
    }

    /// Re-detect volumes of an evidence item (after volume or filesystem support improves)
    /// and drop its cached layout. Stored hits keep their offsets; call `reattribute` after.
    pub fn refresh_volumes(&self, id: EvidenceId) -> Result<Vec<Volume>> {
        let source = self.source(id)?;
        let volumes = VolumeScanner::default().scan(source.as_ref());
        {
            let mut conn = self.conn.lock();
            let tx = conn.transaction().map_err(db)?;
            tx.execute("DELETE FROM volumes WHERE evidence_id = ?1", [id.get()]).map_err(db)?;
            for v in &volumes {
                tx.execute(
                    "INSERT INTO volumes (evidence_id, idx, start, len, fs, origin, label) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![id.get(), v.index, v.range.start() as i64, v.range.len() as i64, format!("{:?}", v.fs), format!("{:?}", v.origin), v.label],
                )
                .map_err(db)?;
            }
            tx.commit().map_err(db)?;
        }
        self.layouts.lock().remove(&id);
        Ok(volumes)
    }

    /// Append volumes found outside the volume scanner (e.g. imported from an R-Studio scan
    /// and verified by the caller); they get the next free indices. Returns them as stored.
    pub fn add_volumes(&self, id: EvidenceId, volumes: &[Volume]) -> Result<Vec<Volume>> {
        let mut stored = Vec::new();
        {
            let mut conn = self.conn.lock();
            let next: u32 = conn
                .query_row("SELECT COALESCE(MAX(idx) + 1, 0) FROM volumes WHERE evidence_id = ?1", [id.get()], |r| r.get(0))
                .map_err(db)?;
            let tx = conn.transaction().map_err(db)?;
            for (i, v) in volumes.iter().enumerate() {
                let v = Volume { index: next + i as u32, ..v.clone() };
                tx.execute(
                    "INSERT INTO volumes (evidence_id, idx, start, len, fs, origin, label) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![id.get(), v.index, v.range.start() as i64, v.range.len() as i64, format!("{:?}", v.fs), format!("{:?}", v.origin), v.label],
                )
                .map_err(db)?;
                stored.push(v);
            }
            tx.commit().map_err(db)?;
        }
        self.layouts.lock().remove(&id);
        Ok(stored)
    }

    pub fn evidence(&self) -> Result<Vec<EvidenceRecord>> {
        let conn = self.readers.get().map_err(db)?;
        let mut stmt = conn.prepare("SELECT id, info FROM evidence ORDER BY id").map_err(db)?;
        let rows: Vec<(u32, String)> =
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(db)?.collect::<rusqlite::Result<_>>().map_err(db)?;
        let mut out = Vec::new();
        for (id, info) in rows {
            let id = EvidenceId::new(id);
            let info: SourceInfo = serde_json::from_str(&info).map_err(|e| Error::Other(e.to_string()))?;
            out.push(EvidenceRecord { id, info, volumes: Self::load_volumes(&conn, id)? });
        }
        Ok(out)
    }

    fn load_volumes(conn: &Connection, id: EvidenceId) -> Result<Vec<Volume>> {
        let mut stmt = conn
            .prepare("SELECT idx, start, len, fs, origin, label FROM volumes WHERE evidence_id = ?1 ORDER BY idx")
            .map_err(db)?;
        let rows = stmt
            .query_map([id.get()], |r| {
                Ok((r.get::<_, u32>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?))
            })
            .map_err(db)?;
        rows.filter_map(|r| r.ok())
            .map(|(index, start, len, fs, origin, label)| {
                Ok(Volume {
                    index,
                    range: ByteRange::new(start as u64, len as u64),
                    fs: parse_enum(fs).unwrap_or(strata_volume::FsKind::Unknown),
                    origin: parse_enum(origin).unwrap_or(strata_volume::VolumeOrigin::Recovered),
                    label,
                })
            })
            .collect()
    }

    pub fn source(&self, id: EvidenceId) -> Result<Arc<dyn BlockSource>> {
        if let Some(s) = self.sources.lock().get(&id) {
            return Ok(s.clone());
        }
        let record = self.record(id)?;
        let source = open_source(&record.info.location, Some(&self.root.join("cache")))?;
        self.sources.lock().insert(id, source.clone());
        Ok(source)
    }

    pub fn record(&self, id: EvidenceId) -> Result<EvidenceRecord> {
        self.evidence()?.into_iter().find(|e| e.id == id).ok_or_else(|| Error::Other(format!("no evidence {id}")))
    }

    /// Drop the cached layout so the next [`Case::layout`] parses the volumes again.
    pub(crate) fn forget_layout(&self, id: EvidenceId) {
        self.layouts.lock().remove(&id);
    }

    /// Parsed filesystems of an evidence item (built once, then shared).
    pub fn layout(&self, id: EvidenceId) -> Result<Arc<EvidenceLayout>> {
        if let Some(l) = self.layouts.lock().get(&id) {
            return Ok(l.clone());
        }
        let layout = Arc::new(EvidenceLayout::build(&self.source(id)?, &self.record(id)?.volumes));
        self.layouts.lock().insert(id, layout.clone());
        Ok(layout)
    }

    /// Run (or resume) the single-pass scan of one evidence item and store attributed hits.
    pub fn scan(&self, id: EvidenceId, scanner: &Scanner, control: &ScanControl) -> Result<ScanSummary> {
        self.scan_with(id, scanner, control, SAVE_EVERY, &mut |_, _| Ok(()))
    }

    /// [`scan`](Self::scan) with a hook that runs inside every transaction storing hits and
    /// the watermark (to save a job checkpoint atomically with them). Hits commit with every
    /// chunk that has any; the watermark at least every `save_every`. A hook error rolls that
    /// transaction back and stops the scan.
    pub fn scan_with(
        &self,
        id: EvidenceId,
        scanner: &Scanner,
        control: &ScanControl,
        save_every: Duration,
        on_commit: ScanCommit<'_>,
    ) -> Result<ScanSummary> {
        let source = self.source(id)?;
        let layout = self.layout(id)?;
        let detectors = scanner.detector_ids().join(",");
        let start = self.resume_point(id, &detectors)?;
        let range = ByteRange::from_bounds(start, source.len());
        let mut last_save = Instant::now();
        let mut failure: Option<Error> = None;
        let mut cap = RepeatCap::default();
        let summary = scanner.run(source.as_ref(), range, control, |hits| {
            if failure.is_some() || (hits.is_empty() && last_save.elapsed() < save_every) {
                return;
            }
            let attributed: Vec<_> = hits.into_iter().map(|h| { let a = layout.attribute(h.offset); (h, a) }).collect();
            let (attributed, overflow) = cap.filter(attributed);
            let mark = control.snapshot().watermark.max(start);
            let stored = self.write(|w| {
                w.hits(id, &attributed)?;
                w.repeats(id, &overflow)?;
                w.scan_progress(id, source.len(), mark, false, &detectors)?;
                on_commit(w, mark)
            });
            match stored {
                Ok(()) => last_save = Instant::now(),
                Err(e) => {
                    failure = Some(e);
                    control.cancel();
                }
            }
        })?;
        if let Some(e) = failure {
            return Err(e);
        }
        let mark = control.snapshot().watermark.max(start);
        self.write(|w| {
            w.scan_progress(id, source.len(), mark, summary.completed, &detectors)?;
            on_commit(w, mark)
        })?;
        Ok(summary)
    }

    /// Where the next scan with `detectors` starts: the stored watermark of an unfinished
    /// scan by the same detectors, else 0.
    pub fn resume_point(&self, id: EvidenceId, detectors: &str) -> Result<u64> {
        let conn = self.readers.get().map_err(db)?;
        let row: Option<(i64, bool, String)> = conn
            .query_row("SELECT watermark, completed, detectors FROM scans WHERE evidence_id = ?1", [id.get()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()
            .map_err(db)?;
        Ok(match row {
            Some((mark, false, d)) if d == detectors => mark as u64,
            _ => 0,
        })
    }

    /// `(watermark, total, completed)` of the last scan, if any.
    pub fn scan_state(&self, id: EvidenceId) -> Result<Option<(u64, u64, bool)>> {
        self.readers
            .get()
            .map_err(db)?
            .query_row("SELECT watermark, range_len, completed FROM scans WHERE evidence_id = ?1", [id.get()], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64, r.get(2)?))
            })
            .optional()
            .map_err(db)
    }

    /// Count of significant findings per `cell_len`-sized bucket of the disk.
    pub fn finding_density(&self, id: EvidenceId, cell_len: u64) -> Result<std::collections::HashMap<u64, u32>> {
        let conn = self.readers.get().map_err(db)?;
        let mut stmt = conn
            .prepare(
                "SELECT offset / ?2, COUNT(*) FROM hits WHERE evidence_id = ?1
                 AND category IN ('PrivateKey','ExtendedKey','Mnemonic','Wallet','Address','Identity') GROUP BY 1",
            )
            .map_err(db)?;
        let rows = stmt
            .query_map(params![id.get(), cell_len.max(1) as i64], |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u32)))
            .map_err(db)?;
        rows.collect::<rusqlite::Result<_>>().map_err(db)
    }

    /// Lower the confidence of findings inside live system files (by path prefix, by a folder
    /// anywhere in the path, e.g. under container layers, or by extension) and tag them in
    /// `details.triage`. Idempotent: tagged hits are skipped.
    pub fn downgrade_system_hits(&self, id: EvidenceId, prefixes: &[&str], folders: &[&str], extensions: &[&str], factor: f32) -> Result<usize> {
        // Rules are crate constants, not user input, so they are inlined into the SQL.
        let path_rule: Vec<String> = prefixes
            .iter()
            .map(|p| format!("lower(file_path) LIKE '{p}%'"))
            .chain(folders.iter().map(|f| format!("lower(file_path) LIKE '{f}%' OR lower(file_path) LIKE '%/{f}%'")))
            .collect();
        let ext_rule: Vec<String> = extensions.iter().map(|e| format!("lower(file_path) LIKE '%.{}'", e)).collect();
        let sql = format!(
            "UPDATE hits SET confidence = confidence * ?2,
                 details = json_set(CASE WHEN json_valid(details) AND details <> 'null' THEN details ELSE '{{}}' END,
                                    '$.triage', 'inside system file')
             WHERE evidence_id = ?1 AND file_state = 'Allocated'
               AND category IN ('PrivateKey','ExtendedKey','Mnemonic','Address','Marker','Identity','Url')
               AND json_extract(CASE WHEN json_valid(details) AND details <> 'null' THEN details ELSE '{{}}' END, '$.triage') IS NULL
               AND ({} OR {})",
            path_rule.join(" OR "),
            ext_rule.join(" OR ")
        );
        self.with_write(|conn| conn.execute(&sql, params![id.get(), factor]))
    }

    /// Recompute volume/file attribution of stored raw-scan hits (after parser upgrades),
    /// without rescanning. File-level hits (wallet files, artefacts, archive members) keep theirs.
    pub fn reattribute(&self, id: EvidenceId) -> Result<usize> {
        let layout = self.layout(id)?;
        let mut conn = self.conn.lock();
        let rows: Vec<(i64, i64)> = {
            let mut stmt = conn
                .prepare("SELECT id, offset FROM hits WHERE evidence_id = ?1 AND detector NOT LIKE 'wallet.%' AND detector NOT LIKE 'artifacts.%' AND detector <> 'identify.mismatch' AND (file_path IS NULL OR file_path NOT LIKE '%!/%')")
                .map_err(db)?;
            let rows = stmt.query_map([id.get()], |r| Ok((r.get(0)?, r.get(1)?))).map_err(db)?;
            rows.collect::<rusqlite::Result<_>>().map_err(db)?
        };
        let tx = conn.transaction().map_err(db)?;
        {
            let mut stmt = tx
                .prepare("UPDATE hits SET volume_idx = ?2, file_path = ?3, file_state = ?4, file_offset = ?5 WHERE id = ?1")
                .map_err(db)?;
            for (hit, offset) in &rows {
                let a = layout.attribute(*offset as u64);
                stmt.execute(params![
                    hit,
                    a.volume,
                    a.file.as_ref().map(|f| f.path.clone()),
                    a.file.as_ref().map(|f| format!("{:?}", f.state)),
                    a.file.as_ref().map(|f| f.file_offset as i64),
                ])
                .map_err(db)?;
            }
        }
        tx.commit().map_err(db)?;
        Ok(rows.len())
    }

    /// Store hits produced outside the raw scan (file-level parsers, carving).
    pub fn store_hits(&self, id: EvidenceId, hits: &[(strata_kernel::scan::Hit, crate::Attribution)]) -> Result<usize> {
        self.write(|w| w.hits(id, hits))
    }

    pub fn hits(&self, q: &HitQuery) -> Result<Vec<StoredHit>> {
        store::query(&*self.readers.get().map_err(db)?, q).map_err(db)
    }

    /// Distinct findings per category at or above `min_confidence`.
    pub fn hit_counts(&self, evidence: Option<EvidenceId>, min_confidence: f32) -> Result<Vec<(HitCategory, u64)>> {
        store::counts(&*self.readers.get().map_err(db)?, evidence, min_confidence).map_err(db)
    }

    /// The connection, held until the guard drops (one transaction at a time).
    pub(crate) fn connection(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.conn.lock()
    }

    pub(crate) fn with_conn_mut<T>(&self, f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>) -> Result<T> {
        f(&mut self.conn.lock()).map_err(db)
    }

    /// Run a read on a pooled read-only connection; never waits for a write transaction.
    pub(crate) fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let conn = self.readers.get().map_err(db)?;
        f(&conn).map_err(db)
    }

    /// Run a single write statement (or a few) on the write connection.
    pub(crate) fn with_write<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        f(&self.conn.lock()).map_err(db)
    }
}
