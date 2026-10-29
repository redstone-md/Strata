//! Whose mail it is: the address most messages of a mailbox are addressed to, and the
//! addresses that sent the messages kept in Sent folders. Both are proof of use that plain
//! From/To headers are not.

use crate::Case;
use serde::Serialize;
use strata_kernel::{EvidenceId, Result, Timestamp};

/// Folder names of sent mail (lowercase).
const SENT_FOLDERS: &[&str] = &["sent", "sent items", "sent mail", "sent messages", "[gmail]/sent mail", "outbox", "отправленные", "исходящие"];
/// Smallest mailbox whose main recipient counts as its owner.
const MIN_MAILBOX: i64 = 3;

/// One address shown to be the owner's by a mailbox.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MailboxTrace {
    /// Case-folded address.
    pub address: String,
    pub evidence: EvidenceId,
    /// The mailbox file (or the folder name when the file is unknown).
    pub path: String,
    /// Sender of messages in a Sent folder (else: main recipient of the mailbox).
    pub sent: bool,
    /// Messages naming the address in that role.
    pub messages: u64,
    /// Messages in the mailbox.
    pub total: u64,
    pub first: Option<Timestamp>,
    pub last: Option<Timestamp>,
}

impl Case {
    /// Main recipients of mailboxes (at least half the messages of a mailbox of three or more)
    /// and senders of sent mail.
    pub fn mailbox_traces(&self) -> Result<Vec<MailboxTrace>> {
        let sent: Vec<String> = SENT_FOLDERS.iter().map(|f| format!("'{f}'")).collect();
        let owners = format!(
            "WITH box AS (SELECT evidence_id, file_path, COUNT(*) n FROM messages WHERE file_path IS NOT NULL GROUP BY 1, 2 HAVING n >= {MIN_MAILBOX})
             SELECT lower(a.address), m.evidence_id, m.file_path, 0, COUNT(*), MAX(box.n), MIN(m.at), MAX(m.at)
             FROM box JOIN messages m ON m.evidence_id = box.evidence_id AND m.file_path = box.file_path
             JOIN message_addresses a ON a.message = m.id
             WHERE instr(lower(m.recipients), lower(a.address)) > 0
             GROUP BY 1, 2, 3 HAVING COUNT(*) * 2 >= MAX(box.n)"
        );
        let senders = format!(
            "SELECT lower(a.address), m.evidence_id, IFNULL(m.file_path, m.folder), 1, COUNT(*), COUNT(*), MIN(m.at), MAX(m.at)
             FROM messages m JOIN message_addresses a ON a.message = m.id
             WHERE lower(m.folder) IN ({}) AND instr(lower(m.sender), lower(a.address)) > 0
             GROUP BY 1, 2, 3",
            sent.join(",")
        );
        self.with_conn(|conn| {
            let mut out = Vec::new();
            for sql in [owners, senders] {
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt.query_map([], |r| {
                    let secs = |i: usize| r.get::<_, Option<i64>>(i).map(|v| v.and_then(Timestamp::from_unix_secs));
                    Ok(MailboxTrace {
                        address: r.get(0)?,
                        evidence: EvidenceId::new(r.get(1)?),
                        path: r.get(2)?,
                        sent: r.get::<_, i64>(3)? != 0,
                        messages: r.get::<_, i64>(4)?.max(0) as u64,
                        total: r.get::<_, i64>(5)?.max(0) as u64,
                        first: secs(6)?,
                        last: secs(7)?,
                    })
                })?;
                for row in rows {
                    out.push(row?);
                }
            }
            Ok(out)
        })
    }
}
