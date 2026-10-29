//! Read connections. The case database runs in WAL mode, so readers see the last committed
//! state without waiting for a writer: the UI keeps rendering while a job holds a long write
//! transaction on the single write connection.

use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags};
use std::ops::Deref;
use std::path::PathBuf;

/// Read-only connections, opened on demand and reused. Never blocks on another reader.
pub(crate) struct ReadPool {
    path: PathBuf,
    idle: Mutex<Vec<Connection>>,
}

impl ReadPool {
    /// Idle connections kept for reuse; more may be open at once under load.
    const KEEP: usize = 4;

    pub fn new(path: PathBuf) -> Self {
        Self { path, idle: Mutex::default() }
    }

    /// A read connection, returned to the pool when the guard drops.
    pub fn get(&self) -> rusqlite::Result<ReadConn<'_>> {
        let conn = match self.idle.lock().pop() {
            Some(conn) => conn,
            None => self.open()?,
        };
        Ok(ReadConn { pool: self, conn: Some(conn) })
    }

    fn open(&self) -> rusqlite::Result<Connection> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI;
        let conn = Connection::open_with_flags(&self.path, flags)?;
        conn.execute_batch("PRAGMA query_only=1; PRAGMA busy_timeout=5000;")?;
        Ok(conn)
    }
}

pub(crate) struct ReadConn<'p> {
    pool: &'p ReadPool,
    conn: Option<Connection>,
}

impl Deref for ReadConn<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("connection present until drop")
    }
}

impl Drop for ReadConn<'_> {
    fn drop(&mut self) {
        let mut idle = self.pool.idle.lock();
        if let Some(conn) = self.conn.take().filter(|_| idle.len() < ReadPool::KEEP) {
            idle.push(conn);
        }
    }
}
