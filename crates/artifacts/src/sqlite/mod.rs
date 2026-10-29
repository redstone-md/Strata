//! SQLite access for browser databases: open an in-memory copy (evidence is never touched, stale
//! `-journal`/`-wal` files are ignored), with raw page-level fallbacks for damaged files.

mod pages;
mod raw;

pub(crate) use pages::SqlitePages;
pub(crate) use raw::{RawUrlScanner, TimeEncoding};

use rusqlite::{Connection, DatabaseName, Row};
use std::ptr::NonNull;
use strata_kernel::{Damage, DamageKind};

pub(crate) const MAGIC: &[u8; 16] = b"SQLite format 3\0";

pub(crate) fn is_sqlite(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// A read-only in-memory database plus the damage seen while querying it.
pub(crate) struct SqliteDb {
    conn: Connection,
    damage: Vec<Damage>,
}

impl SqliteDb {
    /// Open a copy of `data`. WAL-mode headers are switched to rollback mode so SQLite does not
    /// look for a `-wal` file. `Err` when SQLite refuses the bytes.
    pub fn open(data: &[u8]) -> Result<Self, String> {
        if !is_sqlite(data) || data.len() < 512 {
            return Err("not a SQLite database".into());
        }
        let mut conn = Connection::open_in_memory().map_err(|e| e.to_string())?;
        let owned = owned_copy(data).ok_or("sqlite3_malloc failed")?;
        conn.deserialize(DatabaseName::Main, owned, true).map_err(|e| e.to_string())?;
        let db = Self { conn, damage: Vec::new() };
        // Force SQLite to read the schema now so a broken header is reported here.
        db.conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).map_err(|e| e.to_string())?;
        Ok(db)
    }

    pub fn tables(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(mut st) = self.conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")
            && let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0))
        {
            out.extend(rows.flatten().map(|s| s.to_ascii_lowercase()));
        }
        out
    }

    pub fn has_table(&self, name: &str) -> bool {
        self.tables().iter().any(|t| t == name)
    }

    pub fn columns(&self, table: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(mut st) = self.conn.prepare(&format!("PRAGMA table_info(\"{}\")", table.replace('"', "")))
            && let Ok(rows) = st.query_map([], |r| r.get::<_, String>(1))
        {
            out.extend(rows.flatten().map(|s| s.to_ascii_lowercase()));
        }
        out
    }

    /// `col` if the table has it, else `fallback` (an SQL literal), so one query works across
    /// browser versions.
    pub fn col_or(&self, table: &str, col: &str, fallback: &str) -> String {
        if self.columns(table).iter().any(|c| c == col) { col.to_string() } else { format!("{fallback} AS {col}") }
    }

    /// Run `sql`, calling `f` per row. Stops at the first unreadable row and records damage
    /// (truncated files fail mid-scan, after the readable rows were delivered).
    pub fn each(&mut self, sql: &str, mut f: impl FnMut(&Row<'_>)) -> usize {
        let mut n = 0;
        let res = (|| -> rusqlite::Result<()> {
            let mut st = self.conn.prepare(sql)?;
            let mut rows = st.query([])?;
            while let Some(row) = rows.next()? {
                f(row);
                n += 1;
            }
            Ok(())
        })();
        if let Err(e) = res {
            self.damage.push(Damage::new(DamageKind::Corrupt, None, format!("sqlite query stopped after {n} rows: {e}")));
        }
        n
    }

    pub fn take_damage(&mut self) -> Vec<Damage> {
        std::mem::take(&mut self.damage)
    }
}

/// Copy into SQLite-owned memory, patching the WAL read/write versions (bytes 18, 19).
fn owned_copy(data: &[u8]) -> Option<rusqlite::serialize::OwnedData> {
    let len = data.len();
    // SAFETY: `sqlite3_malloc64` returns either null (checked) or a writable block of `len`
    // bytes; we fully initialise it with `copy_nonoverlapping` before handing ownership to
    // `OwnedData`, which frees it with `sqlite3_free`.
    unsafe {
        let ptr = rusqlite::ffi::sqlite3_malloc64(len as u64).cast::<u8>();
        let ptr = NonNull::new(ptr)?;
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.as_ptr(), len);
        let buf = std::slice::from_raw_parts_mut(ptr.as_ptr(), len);
        for b in &mut buf[18..20] {
            if *b == 2 {
                *b = 1;
            }
        }
        Some(rusqlite::serialize::OwnedData::from_raw_nonnull(ptr, len))
    }
}

/// Typed column getters that never fail (NULL / wrong type → default).
pub(crate) trait RowExt {
    fn text(&self, idx: usize) -> String;
    fn int(&self, idx: usize) -> i64;
    fn blob_len(&self, idx: usize) -> usize;
}

impl RowExt for Row<'_> {
    fn text(&self, idx: usize) -> String {
        use rusqlite::types::ValueRef;
        match self.get_ref(idx) {
            Ok(ValueRef::Text(t)) => String::from_utf8_lossy(t).into_owned(),
            Ok(ValueRef::Blob(b)) => String::from_utf8_lossy(b).into_owned(),
            Ok(ValueRef::Integer(i)) => i.to_string(),
            _ => String::new(),
        }
    }

    fn int(&self, idx: usize) -> i64 {
        use rusqlite::types::ValueRef;
        match self.get_ref(idx) {
            Ok(ValueRef::Integer(i)) => i,
            Ok(ValueRef::Real(f)) => f as i64,
            Ok(ValueRef::Text(t)) => std::str::from_utf8(t).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0),
            _ => 0,
        }
    }

    fn blob_len(&self, idx: usize) -> usize {
        use rusqlite::types::ValueRef;
        match self.get_ref(idx) {
            Ok(ValueRef::Blob(b)) | Ok(ValueRef::Text(b)) => b.len(),
            _ => 0,
        }
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use rusqlite::{Connection, DatabaseName};

    /// Build a database with `sql` and return its file bytes.
    pub fn db_bytes(sql: &str) -> Vec<u8> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(sql).unwrap();
        conn.serialize(DatabaseName::Main).unwrap().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_roundtrip_and_garbage() {
        let mut bytes = testutil::db_bytes("CREATE TABLE t(a TEXT); INSERT INTO t VALUES('x'),('y');");
        bytes[18] = 2;
        bytes[19] = 2;
        let mut db = SqliteDb::open(&bytes).unwrap();
        assert!(db.has_table("t"));
        assert_eq!(db.each("SELECT a FROM t", |_| {}), 2);
        assert_eq!(db.col_or("t", "zzz", "0"), "0 AS zzz");
        assert!(SqliteDb::open(b"garbage").is_err());
        let mut junk = MAGIC.to_vec();
        junk.resize(4096, 0xAB);
        assert!(SqliteDb::open(&junk).is_err());
        let _ = SqliteDb::open(&bytes[..600]);
    }
}
