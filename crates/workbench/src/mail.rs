//! Workbench use cases for recovered e-mail: list and search messages, open one, and write a
//! message or one of its attachments out of the evidence. Raw bytes are read again from where
//! the message was found (a file of the listing, or the disk for carved messages).

use crate::explore::recovery::{Item, Recovered, RecoveryWriter};
use crate::workbench::Workbench;
use std::path::Path;
use strata_case::{MessageLocation, MessageQuery, MessageRow, StoredMessage};
use strata_fs::FileId;
use strata_kernel::{Error, EvidenceId, Result};
use strata_mail::{Container, Dbx, Message};

impl Workbench {
    /// Messages matching `q`, oldest first.
    pub fn messages(&self, q: &MessageQuery) -> Result<Vec<MessageRow>> {
        self.case.messages(q)
    }

    pub fn message_count(&self, q: &MessageQuery) -> Result<u64> {
        self.case.message_count(q)
    }

    /// One message with headers, body, attachment list and every place it was found.
    pub fn message(&self, id: i64) -> Result<Option<StoredMessage>> {
        self.case.message(id)
    }

    /// Messages from, to or copying `address` on every disk.
    pub fn messages_with_address(&self, address: &str, limit: usize) -> Result<Vec<MessageRow>> {
        self.case.messages(&MessageQuery { address: Some(address.to_string()), limit, ..MessageQuery::default() })
    }

    /// The message's bytes as stored on the evidence (an RFC 822 message).
    pub fn message_raw(&self, id: i64) -> Result<Vec<u8>> {
        let stored = self.stored_message(id)?;
        self.read_location(stored.row.evidence, &stored.row.location)
    }

    /// Write the message as `.eml` under `<dest>/<disk>/$Mail`.
    pub fn export_message(&self, id: i64, dest: &Path) -> Result<Recovered> {
        let stored = self.stored_message(id)?;
        let raw = self.read_location(stored.row.evidence, &stored.row.location)?;
        let name = format!("message-{id}.eml");
        self.write_out(&stored, dest, &[name], &raw, &stored.message.notes)
    }

    /// Write attachment `index` of a message under `<dest>/<disk>/$Mail/message-<id>`.
    pub fn export_attachment(&self, id: i64, index: usize, dest: &Path) -> Result<Recovered> {
        let stored = self.stored_message(id)?;
        let raw = self.read_location(stored.row.evidence, &stored.row.location)?;
        let (attachment, bytes) =
            Message::attachment(&raw, index).ok_or_else(|| Error::Other(format!("attachment {} is not in the message any more", index + 1)))?;
        let mut damage = Vec::new();
        if (bytes.len() as u64) < attachment.size || (bytes.len() as u64) < stored.message.attachments.get(index).map_or(0, |a| a.size) {
            damage.push("shorter than when the message was read".to_string());
        }
        self.write_out(&stored, dest, &[format!("message-{id}"), attachment.name], &bytes, &damage)
    }

    fn stored_message(&self, id: i64) -> Result<StoredMessage> {
        self.case.message(id)?.ok_or_else(|| Error::Other(format!("no message {id}")))
    }

    fn write_out(&self, stored: &StoredMessage, dest: &Path, name: &[String], bytes: &[u8], damage: &[String]) -> Result<Recovered> {
        let disk = self.case.record(stored.row.evidence)?.info.label;
        let locations: Vec<String> = self.case.evidence()?.into_iter().map(|e| e.info.location).collect();
        let mut writer = RecoveryWriter::open(dest, &locations)?;
        let item = Item {
            source_path: stored.row.location.describe(),
            state: format!("mail ({})", stored.row.location.state.name()),
            size: bytes.len() as u64,
            intact: bytes.len() as u64,
            damage: damage.to_vec(),
        };
        let mut components = vec![disk, "$Mail".to_string()];
        components.extend(name.iter().cloned());
        let mut read = |off: u64, buf: &mut [u8]| {
            let start = (off as usize).min(bytes.len());
            let n = buf.len().min(bytes.len() - start);
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            Ok(n)
        };
        let recovered = writer.write(&components, &item, &mut read)?;
        writer.finish()?;
        Ok(recovered)
    }

    /// Bytes of a message where it was found.
    fn read_location(&self, evidence: EvidenceId, l: &MessageLocation) -> Result<Vec<u8>> {
        let (Some(volume), Some(idx)) = (l.volume, l.file_idx) else {
            return self.case.source(evidence)?.read_vec(l.offset, l.len as usize);
        };
        let layout = self.case.layout(evidence)?;
        let (_, fs) = layout.filesystem(volume).ok_or_else(|| Error::Other(format!("volume {volume} did not parse")))?;
        let read = |at: u64, len: usize| {
            let mut buf = vec![0u8; len];
            let n = fs.read(FileId::new(idx), at, &mut buf).ok()?;
            buf.truncate(n);
            Some(buf)
        };
        Ok(match l.container {
            Container::Dbx => Dbx::read_message(read, l.offset),
            _ => read(l.offset, l.len as usize).unwrap_or_default(),
        })
    }
}
