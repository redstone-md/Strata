//! Disk content searches and their results (`searches`, `search_results`). The store owns its
//! tables and creates them on first use.

use crate::Case;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use strata_kernel::{EvidenceId, Result};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS searches (
    id INTEGER PRIMARY KEY,
    query TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL,
    results INTEGER NOT NULL DEFAULT 0,
    truncated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS search_results (
    search_id INTEGER NOT NULL REFERENCES searches(id),
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    offset INTEGER NOT NULL,
    len INTEGER NOT NULL,
    encoding TEXT NOT NULL,
    context BLOB NOT NULL,
    context_start INTEGER NOT NULL,
    preview TEXT NOT NULL,
    match_from INTEGER NOT NULL,
    match_to INTEGER NOT NULL,
    volume_idx INTEGER,
    file_path TEXT,
    file_state TEXT,
    file_offset INTEGER,
    location TEXT NOT NULL,
    PRIMARY KEY (search_id, evidence_id, offset, encoding)
);
"#;

/// One stored search: what was asked and how it ended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRecord {
    pub id: i64,
    /// The query as JSON (owned by the search domain).
    pub query: String,
    pub summary: String,
    pub created_at: i64,
    /// `running`, `done`, `cancelled`, `failed: ...`
    pub state: String,
    pub results: u64,
    /// The result cap was reached; more matches exist.
    pub truncated: bool,
}

/// One match, attributed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchResultRow {
    pub search_id: i64,
    pub evidence: EvidenceId,
    pub offset: u64,
    pub len: u32,
    pub encoding: String,
    /// Raw bytes around the match.
    pub context: Vec<u8>,
    /// Absolute offset of `context[0]`.
    pub context_start: u64,
    /// `context` rendered as text, control bytes replaced.
    pub preview: String,
    /// Character range of the match inside `preview`.
    pub match_from: u32,
    pub match_to: u32,
    pub volume: Option<u32>,
    pub file_path: Option<String>,
    pub file_state: Option<String>,
    pub file_offset: Option<u64>,
    /// `live`, `deleted`, `orphan`, `unallocated`, `deleted partition`, `outside volumes`.
    pub location: String,
}

fn ensure(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA)
}

impl Case {
    /// Start a search record; results are added with [`Case::store_search_results`].
    pub fn begin_search(&self, query_json: &str, summary: &str) -> Result<i64> {
        self.with_write(|conn| {
            ensure(conn)?;
            conn.execute(
                "INSERT INTO searches (query, summary, created_at, state) VALUES (?1, ?2, strftime('%s','now'), 'running')",
                params![query_json, summary],
            )?;
            Ok(conn.last_insert_rowid())
        })
    }

    pub fn finish_search(&self, id: i64, state: &str, truncated: bool) -> Result<()> {
        self.with_write(|conn| {
            ensure(conn)?;
            conn.execute(
                "UPDATE searches SET state = ?2, truncated = ?3,
                 results = (SELECT COUNT(*) FROM search_results WHERE search_id = ?1) WHERE id = ?1",
                params![id, state, truncated],
            )
            .map(|_| ())
        })
    }

    /// Insert results (duplicates of the same match are ignored). Returns rows added.
    pub fn store_search_results(&self, rows: &[SearchResultRow]) -> Result<usize> {
        self.write(|w| w.search_results(rows))
    }

    pub fn search_record(&self, id: i64) -> Result<Option<SearchRecord>> {
        self.with_conn(|conn| {
            ensure(conn)?;
            conn.query_row("SELECT id, query, summary, created_at, state, results, truncated FROM searches WHERE id = ?1", [id], record)
                .optional()
        })
    }

    /// Searches, newest first.
    pub fn searches(&self, limit: usize) -> Result<Vec<SearchRecord>> {
        self.with_conn(|conn| {
            ensure(conn)?;
            let mut stmt = conn.prepare(
                "SELECT id, query, summary, created_at, state, results, truncated FROM searches ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map([limit as i64], record)?;
            rows.collect()
        })
    }

    /// Results of one search in disk order, a page at a time.
    pub fn search_results(&self, search: i64, offset: usize, limit: usize) -> Result<Vec<SearchResultRow>> {
        self.with_conn(|conn| {
            ensure(conn)?;
            let mut stmt = conn.prepare(
                "SELECT search_id, evidence_id, offset, len, encoding, context, context_start, preview, match_from, match_to,
                        volume_idx, file_path, file_state, file_offset, location
                 FROM search_results WHERE search_id = ?1 ORDER BY evidence_id, offset LIMIT ?2 OFFSET ?3",
            )?;
            let rows = stmt.query_map(params![search, limit as i64, offset as i64], |r| {
                Ok(SearchResultRow {
                    search_id: r.get(0)?,
                    evidence: EvidenceId::new(r.get(1)?),
                    offset: r.get::<_, i64>(2)? as u64,
                    len: r.get(3)?,
                    encoding: r.get(4)?,
                    context: r.get(5)?,
                    context_start: r.get::<_, i64>(6)? as u64,
                    preview: r.get(7)?,
                    match_from: r.get(8)?,
                    match_to: r.get(9)?,
                    volume: r.get(10)?,
                    file_path: r.get(11)?,
                    file_state: r.get(12)?,
                    file_offset: r.get::<_, Option<i64>>(13)?.map(|v| v as u64),
                    location: r.get(14)?,
                })
            })?;
            rows.collect()
        })
    }

    pub fn search_result_count(&self, search: i64) -> Result<u64> {
        self.with_conn(|conn| {
            ensure(conn)?;
            conn.query_row("SELECT COUNT(*) FROM search_results WHERE search_id = ?1", [search], |r| r.get::<_, i64>(0)).map(|n| n as u64)
        })
    }
}

fn record(r: &rusqlite::Row<'_>) -> rusqlite::Result<SearchRecord> {
    Ok(SearchRecord {
        id: r.get(0)?,
        query: r.get(1)?,
        summary: r.get(2)?,
        created_at: r.get(3)?,
        state: r.get(4)?,
        results: r.get::<_, i64>(5)? as u64,
        truncated: r.get(6)?,
    })
}

/// Insert inside the caller's transaction; duplicates of the same match are ignored.
pub(crate) fn insert_results(conn: &Connection, rows: &[SearchResultRow]) -> rusqlite::Result<usize> {
    ensure(conn)?;
    let mut stmt = conn.prepare_cached(
        "INSERT OR IGNORE INTO search_results (search_id, evidence_id, offset, len, encoding, context,
         context_start, preview, match_from, match_to, volume_idx, file_path, file_state, file_offset, location)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
    )?;
    let mut n = 0;
    for r in rows {
        n += stmt.execute(params![
            r.search_id,
            r.evidence.get(),
            r.offset as i64,
            r.len,
            r.encoding,
            r.context,
            r.context_start as i64,
            r.preview,
            r.match_from,
            r.match_to,
            r.volume,
            r.file_path,
            r.file_state,
            r.file_offset.map(|o| o as i64),
            r.location
        ])?;
    }
    Ok(n)
}
