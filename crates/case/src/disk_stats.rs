//! Aggregated reads for judging a disk's evidence: file index tallies per volume and state,
//! files under chosen folders or with chosen names, event counts per parser, where findings
//! lie, and whether a step finished. The caller says which folders, names and kinds matter;
//! nothing here knows what a wiped disk looks like.

use crate::Case;
use crate::activity::params;
use rusqlite::ToSql;
use strata_kernel::{EvidenceId, Result, Timestamp};

/// Index entries of one volume in one state (`Allocated`, `Deleted`, `Orphan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTally {
    pub volume: u32,
    pub state: String,
    pub files: u64,
    pub folders: u64,
    /// Summed size of the files.
    pub bytes: u64,
}

/// Files of one state under one child folder of a root (`Users/` + `alice`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderTally {
    pub volume: u32,
    pub root: String,
    /// First path element under the root.
    pub child: String,
    pub state: String,
    pub files: u64,
    pub bytes: u64,
}

/// One index entry with the fields a consistency check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedFile {
    pub volume: u32,
    pub path: String,
    pub state: String,
    pub size: u64,
    pub created: Option<Timestamp>,
}

/// Findings of one placement: the state of the file they lie in, `None` outside any file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HitTally {
    pub state: Option<String>,
    pub count: u64,
}

fn marks(first: usize, n: usize) -> String {
    (first..first + n).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ")
}

impl Case {
    /// Files, folders and bytes per volume and entry state.
    pub fn file_tallies(&self, evidence: EvidenceId) -> Result<Vec<FileTally>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT volume_idx, state, SUM(is_dir = 0), SUM(is_dir != 0), SUM(CASE WHEN is_dir = 0 THEN MAX(size, 0) ELSE 0 END)
                 FROM files WHERE evidence_id = ?1 GROUP BY volume_idx, state",
            )?;
            let rows = stmt.query_map([evidence.get()], |r| {
                Ok(FileTally {
                    volume: r.get(0)?,
                    state: r.get(1)?,
                    files: r.get::<_, i64>(2)? as u64,
                    folders: r.get::<_, i64>(3)? as u64,
                    bytes: r.get::<_, i64>(4)? as u64,
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// Entries at exactly these paths (relative to the volume root, as the index stores them).
    pub fn files_at(&self, evidence: EvidenceId, paths: &[&str]) -> Result<Vec<IndexedFile>> {
        let sql = format!(
            "SELECT volume_idx, path, state, size, created FROM files WHERE evidence_id = ?1 AND path IN ({}) ORDER BY volume_idx, file_idx",
            marks(2, paths.len())
        );
        self.indexed_files(evidence, &sql, paths)
    }

    /// Files whose name starts with one of `stems` (any case), at most `limit`.
    pub fn files_named_like(&self, evidence: EvidenceId, stems: &[&str], limit: usize) -> Result<Vec<IndexedFile>> {
        if stems.is_empty() {
            return Ok(Vec::new());
        }
        let likes: Vec<String> = (0..stems.len()).map(|i| format!("name LIKE ?{} ESCAPE '\\'", i + 2)).collect();
        let sql = format!(
            "SELECT volume_idx, path, state, size, created FROM files WHERE evidence_id = ?1 AND is_dir = 0 AND ({})
             ORDER BY volume_idx, file_idx LIMIT {limit}",
            likes.join(" OR ")
        );
        let patterns: Vec<String> = stems.iter().map(|s| format!("{}%", escape_like(s))).collect();
        self.indexed_files(evidence, &sql, &patterns.iter().map(String::as_str).collect::<Vec<_>>())
    }

    fn indexed_files(&self, evidence: EvidenceId, sql: &str, args: &[&str]) -> Result<Vec<IndexedFile>> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let bound = params(evidence, &args);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(bound.iter().map(|a| a.as_ref())), |r| {
                Ok(IndexedFile {
                    volume: r.get(0)?,
                    path: r.get(1)?,
                    state: r.get(2)?,
                    size: r.get::<_, i64>(3)?.max(0) as u64,
                    created: r.get::<_, Option<i64>>(4)?.and_then(Timestamp::from_unix_secs),
                })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// Files under each root folder (`Users/`, with the slash), counted per volume, child
    /// folder and state. The root folder's own children that are files count under their name.
    pub fn folder_tallies(&self, evidence: EvidenceId, roots: &[&str]) -> Result<Vec<FolderTally>> {
        let mut out = Vec::new();
        for root in roots {
            let sql = "SELECT volume_idx, child, state, SUM(is_dir = 0), SUM(CASE WHEN is_dir = 0 THEN MAX(size, 0) ELSE 0 END) FROM (
                     SELECT volume_idx, state, is_dir, size,
                            CASE WHEN instr(rest, '/') > 0 THEN substr(rest, 1, instr(rest, '/') - 1) ELSE rest END AS child
                     FROM (SELECT volume_idx, state, is_dir, size, substr(path, length(?2) + 1) AS rest
                           FROM files WHERE evidence_id = ?1 AND path LIKE ?3 ESCAPE '\\'))
                 WHERE child != '' GROUP BY volume_idx, child, state";
            let pattern = format!("{}%", escape_like(root));
            let rows: Vec<FolderTally> = self.with_conn(|conn| {
                let mut stmt = conn.prepare(sql)?;
                let rows = stmt.query_map(rusqlite::params![evidence.get(), root, pattern], |r| {
                    Ok(FolderTally {
                        volume: r.get(0)?,
                        root: root.to_string(),
                        child: r.get(1)?,
                        state: r.get(2)?,
                        files: r.get::<_, i64>(3)? as u64,
                        bytes: r.get::<_, i64>(4)? as u64,
                    })
                })?;
                Ok(rows.filter_map(|r| r.ok()).collect())
            })?;
            out.extend(rows);
        }
        Ok(out)
    }

    /// Events of the given kinds counted per parser (`chrome.history` → 43 537).
    pub fn event_counts_by_artifact(&self, evidence: EvidenceId, kinds: &[&str]) -> Result<Vec<(String, u64)>> {
        let sql = format!("SELECT artifact, COUNT(*) FROM events WHERE evidence_id = ?1 AND kind IN ({}) GROUP BY artifact", marks(2, kinds.len()));
        let args: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
        let bound = params(evidence, &args);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(bound.iter().map(|a| a.as_ref())), |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)))?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// Findings at or above `min_confidence`, outside `skipped` categories, counted by the
    /// state of the file they lie in (`None`: outside any listed file).
    pub fn hit_placement(&self, evidence: EvidenceId, min_confidence: f32, skipped: &[&str]) -> Result<Vec<HitTally>> {
        let sql = format!(
            "SELECT CASE WHEN file_path IS NULL THEN NULL ELSE file_state END, COUNT(*) FROM hits
             WHERE evidence_id = ?1 AND confidence >= ?2 AND category NOT IN ({}) GROUP BY 1",
            marks(3, skipped.len())
        );
        let mut bound: Vec<Box<dyn ToSql>> = vec![Box::new(evidence.get()), Box::new(f64::from(min_confidence))];
        bound.extend(skipped.iter().map(|s| Box::new(s.to_string()) as Box<dyn ToSql>));
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(bound.iter().map(|a| a.as_ref())), |r| {
                Ok(HitTally { state: r.get(0)?, count: r.get::<_, i64>(1)? as u64 })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// Jobs of `kind` (`IndexFiles`) that finished for this evidence item.
    pub fn finished_jobs(&self, evidence: EvidenceId, kind: &str) -> Result<u64> {
        self.with_conn(|conn| {
            conn.query_row("SELECT COUNT(*) FROM jobs WHERE evidence_id = ?1 AND kind = ?2 AND state = 'Done'", rusqlite::params![evidence.get(), kind], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n as u64)
        })
    }
}

/// `text` as a literal inside a `LIKE ... ESCAPE '\'` pattern.
fn escape_like(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_fs::{EntryState, FileEntry};
    use strata_kernel::scan::{Hit, HitCategory};
    use strata_timeline::{EventKind, EventSource, TimelineEvent};

    fn entry(path: &str, size: u64, is_dir: bool, state: EntryState) -> FileEntry {
        let name = path.rsplit('/').next().unwrap_or(path);
        let mut e = FileEntry::new(name, is_dir, state, 0);
        e.path = path.into();
        e.size = size;
        e.times.created = Timestamp::from_unix_secs(1_300_000_000);
        e
    }

    #[test]
    fn tallies_folders_names_events_and_findings() {
        let dir = tempfile::tempdir().unwrap();
        let case = Case::open(&dir.path().join("c.strata")).unwrap();
        let img = dir.path().join("d.img");
        std::fs::write(&img, vec![0u8; 4096]).unwrap();
        let id = case.add_evidence(&img.display().to_string()).unwrap().id;
        let entries = [
            entry("$MFT", 262_144, false, EntryState::Allocated),
            entry("Users", 0, true, EntryState::Allocated),
            entry("Users/alice", 0, true, EntryState::Allocated),
            entry("Users/alice/notes.txt", 100, false, EntryState::Allocated),
            entry("Users/alice/old.doc", 50, false, EntryState::Deleted),
            entry("Users/bob_x", 0, true, EntryState::Allocated),
            entry("Program Files/CCleaner/CCleaner64.exe", 9, false, EntryState::Allocated),
            entry("Usersbackup/x.txt", 1, false, EntryState::Allocated),
        ];
        case.write(|w| w.files(id, 0, &entries).map(|_| ())).unwrap();

        let tallies = case.file_tallies(id).unwrap();
        let live = tallies.iter().find(|t| t.state == "Allocated").unwrap();
        assert_eq!((live.files, live.folders, live.bytes), (4, 3, 262_144 + 100 + 9 + 1));

        let mft = case.files_at(id, &["$MFT"]).unwrap();
        assert_eq!((mft.len(), mft[0].size, mft[0].created), (1, 262_144, Timestamp::from_unix_secs(1_300_000_000)));

        let folders = case.folder_tallies(id, &["Users/"]).unwrap();
        let alice: Vec<_> = folders.iter().filter(|f| f.child == "alice").map(|f| (f.state.as_str(), f.files, f.bytes)).collect();
        assert_eq!(alice.len(), 2);
        assert!(alice.contains(&("Allocated", 1, 100)) && alice.contains(&("Deleted", 1, 50)));
        assert!(folders.iter().any(|f| f.child == "bob_x" && f.files == 0), "an empty profile still shows");
        assert!(folders.iter().all(|f| f.child != "x.txt"), "Usersbackup is not under Users/");

        let named = case.files_named_like(id, &["ccleaner", "sdel_"], 10).unwrap();
        assert_eq!(named.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["Program Files/CCleaner/CCleaner64.exe"]);

        let ev = |kind, artifact: &str| TimelineEvent::new(Timestamp::from_unix_secs(1_300_000_000).unwrap(), kind, "t", EventSource::new(artifact, "p"));
        case.write(|w| w.volume_events(id, 0, &[ev(EventKind::UrlVisited, "chrome.history"), ev(EventKind::UrlVisited, "chrome.history"), ev(EventKind::Cookie, "firefox.cookies")]))
            .unwrap();
        let counts = case.event_counts_by_artifact(id, &["UrlVisited"]).unwrap();
        assert_eq!(counts, vec![("chrome.history".to_string(), 2)]);

        let hit = |value: &str, confidence: f32, category| Hit::new("t", category, 0, 1).value(value).confidence(strata_kernel::Confidence::new(confidence));
        let in_file = crate::Attribution {
            volume: Some(0),
            file: Some(crate::FileRef { path: "Users/alice/old.doc".into(), state: EntryState::Deleted, file_offset: 0 }),
        };
        case.store_hits(
            id,
            &[
                (hit("a", 0.8, HitCategory::Address), in_file),
                (hit("b", 0.8, HitCategory::Address), crate::Attribution::default()),
                (hit("c", 0.1, HitCategory::Address), crate::Attribution::default()),
                (hit("d", 0.8, HitCategory::Partition), crate::Attribution::default()),
            ],
        )
        .unwrap();
        let mut placed = case.hit_placement(id, 0.2, &["Partition"]).unwrap();
        placed.sort_by(|a, b| a.state.cmp(&b.state));
        assert_eq!(placed, vec![HitTally { state: None, count: 1 }, HitTally { state: Some("Deleted".into()), count: 1 }]);

        assert_eq!(case.finished_jobs(id, "IndexFiles").unwrap(), 0);
        let job = case.add_job(1, id, "IndexFiles", "Index", "Queued").unwrap();
        case.update_job(job, "Done", "", crate::JobStamp::Finished).unwrap();
        assert_eq!(case.finished_jobs(id, "IndexFiles").unwrap(), 1);
    }
}
