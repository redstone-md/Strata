//! SQLite schema, created idempotently. Bump `VERSION` and add a migration step on changes.

use rusqlite::Connection;

pub const VERSION: i64 = 3;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    label TEXT NOT NULL,
    location TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    len INTEGER NOT NULL,
    added_at INTEGER NOT NULL,
    info TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS volumes (
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    idx INTEGER NOT NULL,
    start INTEGER NOT NULL,
    len INTEGER NOT NULL,
    fs TEXT NOT NULL,
    origin TEXT NOT NULL,
    label TEXT NOT NULL,
    PRIMARY KEY (evidence_id, idx)
);

CREATE TABLE IF NOT EXISTS scans (
    evidence_id INTEGER PRIMARY KEY REFERENCES evidence(id),
    range_start INTEGER NOT NULL,
    range_len INTEGER NOT NULL,
    watermark INTEGER NOT NULL,
    completed INTEGER NOT NULL,
    detectors TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hits (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    detector TEXT NOT NULL,
    category TEXT NOT NULL,
    offset INTEGER NOT NULL,
    len INTEGER NOT NULL,
    confidence REAL NOT NULL,
    label TEXT NOT NULL,
    value TEXT NOT NULL,
    details TEXT NOT NULL,
    volume_idx INTEGER,
    file_path TEXT,
    file_state TEXT,
    file_offset INTEGER,
    UNIQUE (evidence_id, detector, offset, value)
);
CREATE INDEX IF NOT EXISTS hits_value ON hits(category, value);
CREATE INDEX IF NOT EXISTS hits_evidence ON hits(evidence_id, category);

CREATE TABLE IF NOT EXISTS files (
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    volume_idx INTEGER NOT NULL,
    file_idx INTEGER NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    is_dir INTEGER NOT NULL,
    state TEXT NOT NULL,
    created INTEGER,
    modified INTEGER,
    accessed INTEGER,
    changed INTEGER,
    sha256 TEXT,
    detected_type TEXT,
    extension_mismatch INTEGER NOT NULL DEFAULT 0,
    type_notes TEXT,
    PRIMARY KEY (evidence_id, volume_idx, file_idx)
);
CREATE INDEX IF NOT EXISTS files_path ON files(path);
CREATE INDEX IF NOT EXISTS files_hash ON files(sha256);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    artifact TEXT NOT NULL,
    path TEXT NOT NULL,
    deleted INTEGER NOT NULL,
    crypto INTEGER NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_at ON events(at);
CREATE INDEX IF NOT EXISTS events_evidence ON events(evidence_id, at);

CREATE TABLE IF NOT EXISTS facts (
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    artifact TEXT NOT NULL,
    source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS archive_members (
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    archive_path TEXT NOT NULL,
    member_path TEXT NOT NULL,
    depth INTEGER NOT NULL,
    size INTEGER,
    packed INTEGER,
    recovered INTEGER NOT NULL,
    encrypted INTEGER NOT NULL,
    detected_type TEXT,
    extension_mismatch INTEGER NOT NULL,
    modified INTEGER,
    damage TEXT NOT NULL,
    PRIMARY KEY (evidence_id, member_path)
);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    pipeline INTEGER,
    evidence_id INTEGER,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    state TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    checkpoint TEXT,
    done INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    owner_pid INTEGER,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS balances (
    address TEXT PRIMARY KEY,
    funded_sat INTEGER NOT NULL,
    spent_sat INTEGER NOT NULL,
    tx_count INTEGER NOT NULL,
    mempool_delta_sat INTEGER NOT NULL,
    source TEXT NOT NULL,
    checked_at INTEGER NOT NULL
);
"#;

pub fn apply(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;
    conn.execute_batch(SCHEMA)?;
    conn.execute_batch(crate::insights::SCHEMA)?;
    conn.execute_batch(crate::messages::SCHEMA)?;
    migrate(conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?1)",
        [VERSION.to_string()],
    )?;
    Ok(())
}

/// Columns added after a case may already exist on disk. `ADD COLUMN` fails harmlessly with
/// "duplicate column" when the column is already there.
/// `hits.repeats`: copies beyond the stored ones (see `repeats.rs`).
/// `events.volume`, `facts.volume`: the volume an artefact was read from (NULL in older cases).
const ADDED_COLUMNS: &[(&str, &str)] = &[
    ("files", "type_notes TEXT"),
    ("hits", "repeats INTEGER NOT NULL DEFAULT 0"),
    ("events", "volume INTEGER"),
    ("facts", "volume INTEGER"),
];

/// Indexes over added columns or added after cases already existed.
const ADDED_INDEXES: &str = "CREATE INDEX IF NOT EXISTS events_kind ON events(evidence_id, kind, at);
CREATE INDEX IF NOT EXISTS facts_key ON facts(evidence_id, key);";

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    for (table, column) in ADDED_COLUMNS {
        match conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column}"), []) {
            Err(rusqlite::Error::SqliteFailure(_, Some(msg))) if msg.contains("duplicate column") => {}
            other => {
                other?;
            }
        }
    }
    conn.execute_batch(ADDED_INDEXES)
}
