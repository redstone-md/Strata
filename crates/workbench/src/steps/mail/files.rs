//! Mail files of the listing: chosen by name (extension, Thunderbird folder files), by the
//! content type the classify step recorded, or as extensionless files under a mail folder;
//! then read by what their content turns out to be.

use super::{MailCursor, Pending};
use crate::jobs::context::StepContext;
use std::collections::HashMap;
use strata_case::{EvidenceLayout, FileTypes, FoundMessage, MessageLocation, MessageState};
use strata_fs::{EntryState, ExtentReader, FileEntry, FileSystem};
use strata_identify::TypeId;
use strata_kernel::Result;
use strata_mail::{Container, Dbx, MBOX_WINDOW, MboxReader, Message};
use strata_volume::Volume;

/// Largest `.eml` read whole.
const MAX_EML: usize = 64 << 20;
/// Largest Outlook Express folder read whole (the format itself stops at 2 GB).
const MAX_DBX: usize = 1 << 30;
/// Bytes read to tell what a file holds.
const HEAD: usize = 64 * 1024;

/// A mail file: volume index and entry index.
pub(super) type Candidate = (u32, usize);

/// Every file that may hold mail, in listing order (deleted entries included).
pub(super) fn candidates(layout: &EvidenceLayout, types: &FileTypes) -> Vec<Candidate> {
    let mail_types = [TypeId::Mbox, TypeId::Eml, TypeId::Dbx].map(|t| t.spec().name);
    let mut out = Vec::new();
    for (vol, fs) in layout.filesystems() {
        for (idx, e) in fs.entries().iter().enumerate() {
            if e.is_dir || e.size == 0 {
                continue;
            }
            let typed = types.get(&(vol.index, idx)).is_some_and(|(t, _)| mail_types.contains(&t.as_str()));
            let in_mail_folder = e.extension().is_none() && e.path.to_ascii_lowercase().split(['/', '\\']).any(|c| c.contains("mail"));
            if typed || in_mail_folder || Container::by_name(&e.path).is_some() {
                out.push((vol.index, idx));
            }
        }
    }
    out
}

/// One mail file being read.
struct MailFile<'a> {
    entry: &'a FileEntry,
    volume: u32,
    idx: usize,
    reader: ExtentReader<'a>,
}

impl MailFile<'_> {
    fn location(&self, container: Container, offset: u64, len: u64) -> MessageLocation {
        let state = if self.entry.state == EntryState::Allocated { MessageState::Live } else { MessageState::Deleted };
        MessageLocation { state, container, volume: Some(self.volume), file_idx: Some(self.idx), path: Some(self.entry.path.clone()), offset, len }
    }

    /// The mailbox folder: the file name of an mbox or `.dbx`, the folder of an `.eml`.
    fn folder(&self, container: Container) -> String {
        let path = self.entry.path.replace('\\', "/");
        let mut parts = path.rsplit('/');
        match container {
            Container::Eml => parts.nth(1).unwrap_or_default().to_string(),
            _ => {
                let name = parts.next().unwrap_or_default();
                name.rsplit_once('.').map_or(name, |(stem, _)| stem).to_string()
            }
        }
    }

    fn found(&self, container: Container, offset: u64, raw: &[u8], cut: bool) -> Option<FoundMessage> {
        let mut message = Message::parse(raw)?;
        if cut {
            message.notes.push(format!("message cut at {} MiB", raw.len() >> 20));
        }
        Some(FoundMessage { location: self.location(container, offset, raw.len() as u64), folder: self.folder(container), message })
    }

    /// Read every message into `pending`; returns how many. An mbox resumes at `cur.offset`
    /// and leaves it at the next unread message when the step stops.
    fn read(&self, ctx: &StepContext<'_>, cur: &mut MailCursor, pending: &mut Pending<'_>) -> Result<usize> {
        let head = self.reader.read_all(HEAD)?;
        let Some(container) = Container::sniff(&head).or_else(|| Container::by_name(&self.entry.path)) else { return Ok(0) };
        let mut n = 0;
        match container {
            Container::Mbox => {
                let read = |at: u64, buf: &mut [u8]| self.reader.read(at, buf);
                let mut mbox = MboxReader::new(read, self.entry.size, cur.offset, MBOX_WINDOW);
                while !ctx.should_stop() {
                    let Some(batch) = mbox.next_batch()? else { break };
                    for m in &batch {
                        if let Some(f) = self.found(container, m.span.offset, &m.bytes, m.cut) {
                            pending.push(f);
                            n += 1;
                        }
                    }
                    cur.offset = mbox.position();
                    pending.commit(cur, false)?;
                }
            }
            Container::Dbx => {
                let data = self.reader.read_all(MAX_DBX)?;
                let dbx = Dbx::scan(&data);
                for head in dbx.heads() {
                    if let Some(f) = self.found(container, head as u64, &dbx.message(&data, head), false) {
                        pending.push(f);
                        n += 1;
                    }
                }
            }
            Container::Eml | Container::Carved => {
                let data = self.reader.read_all(MAX_EML)?;
                let cut = self.entry.size > data.len() as u64;
                if let Some(f) = self.found(Container::Eml, 0, &data, cut) {
                    pending.push(f);
                    n += 1;
                }
            }
        }
        Ok(n)
    }
}

/// Read the mail files from `cur.next` on.
pub(super) fn read_all(ctx: &StepContext<'_>, layout: &EvidenceLayout, candidates: &[Candidate], cur: &mut MailCursor, pending: &mut Pending<'_>) -> Result<()> {
    let source = ctx.source()?;
    let filesystems: HashMap<u32, (&Volume, &dyn FileSystem)> = layout.filesystems().map(|(v, fs)| (v.index, (v, fs))).collect();
    while let Some(&(volume, idx)) = candidates.get(cur.next) {
        if ctx.should_stop() {
            return Ok(());
        }
        if let Some((vol, fs)) = filesystems.get(&volume)
            && let Some(entry) = fs.entries().get(idx)
        {
            ctx.current(&entry.path);
            let vol_source = vol.open(source.clone());
            let file = MailFile { entry, volume, idx, reader: ExtentReader::new(vol_source.as_ref(), entry) };
            let n = file.read(ctx, cur, pending)?;
            if ctx.should_stop() {
                return Ok(());
            }
            if n > 0 {
                cur.files += 1;
                ctx.log(format!("{}: {}", entry.path, super::super::count(n, "message", "messages")));
            }
        }
        cur.next += 1;
        cur.offset = 0;
        ctx.control().item_done();
        pending.commit(cur, false)?;
    }
    Ok(())
}
