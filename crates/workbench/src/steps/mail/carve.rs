//! Messages in free space. Only blocks no live file owns (unallocated space, deleted files'
//! clusters, space outside volumes, volumes that did not parse) that the disk index classed
//! as text, or as low-entropy binary (a short message followed by zeroed slack), are looked
//! at; a message found there is read forward from its header block until it ends (see
//! [`strata_mail::carve`]), across block classes if need be.

use super::{MailCursor, Pending};
use crate::jobs::context::StepContext;
use strata_case::{FoundMessage, MessageLocation, MessageState};
use strata_index::{BlockClass, DiskIndex, Ownership};
use strata_kernel::{ByteRange, Result};
use strata_mail::{Container, Message, carve};
use strata_source::BlockSource;

/// Text read per look for header blocks.
const PIECE: u64 = 4 << 20;
/// Read past the piece so a header block straddling its end is seen whole.
const OVERLAP: u64 = 64 * 1024;
/// First read of a message; larger ones are read again with more.
const FIRST_READ: usize = 256 * 1024;
/// Progress unit of the carving phase.
const UNIT: u64 = 1 << 20;
/// Binary blocks up to 5 bits/byte may be text padded with zeros; code and compressed data
/// run higher.
const MAX_BINARY_ENTROPY: u8 = 10;

/// Blocks that may hold a message and no live file owns, coalesced.
pub(super) fn free_text(idx: &DiskIndex) -> Vec<ByteRange> {
    idx.ranges_where(|r| {
        let texty = match r.class() {
            BlockClass::Text => true,
            BlockClass::Binary => r.entropy_bucket() <= MAX_BINARY_ENTROPY,
            _ => false,
        };
        texty && r.ownership() != Ownership::LiveFile
    })
}

pub(super) fn units(len: u64) -> u64 {
    len.div_ceil(UNIT)
}

/// Progress units before position `at` of range number `range`.
pub(super) fn units_before(ranges: &[ByteRange], range: usize, at: u64) -> u64 {
    let whole: u64 = ranges.iter().take(range).map(|r| units(r.len())).sum();
    whole + ranges.get(range).map_or(0, |r| units(at.saturating_sub(r.start()).min(r.len())))
}

/// The message at `at`, and whether its end was seen (not cut by the size cap or the disk end).
fn read_message(source: &dyn BlockSource, at: u64) -> Result<(Vec<u8>, bool)> {
    let mut want = FIRST_READ;
    loop {
        let len = (want as u64).min(source.len().saturating_sub(at)) as usize;
        let mut buf = source.read_vec(at, len)?;
        let (n, ended) = carve::message_len(&buf);
        if ended || len < want || want >= carve::MAX_CARVED {
            buf.truncate(n);
            return Ok((buf, ended));
        }
        want = (want * 4).min(carve::MAX_CARVED);
    }
}

fn found(at: u64, raw: &[u8], ended: bool) -> Option<FoundMessage> {
    let mut message = Message::parse(raw)?;
    if !ended {
        message.notes.push("no end found: cut where the readable text stops".into());
    }
    let location = MessageLocation {
        state: MessageState::Carved,
        container: Container::Carved,
        volume: None,
        file_idx: None,
        path: None,
        offset: at,
        len: raw.len() as u64,
    };
    Some(FoundMessage { location, folder: String::new(), message })
}

pub(super) fn run(ctx: &StepContext<'_>, ranges: &[ByteRange], cur: &mut MailCursor, pending: &mut Pending<'_>) -> Result<()> {
    let source = ctx.source()?;
    while let Some(range) = ranges.get(cur.range) {
        let mut at = cur.at.max(range.start());
        while at < range.end() {
            if ctx.should_stop() {
                return Ok(());
            }
            let end = (at + PIECE).min(range.end());
            ctx.current(&format!("free text {at:#X}"));
            let buf = source.read_vec(at, ((end + OVERLAP).min(source.len()) - at) as usize)?;
            for start in carve::message_starts(&buf).into_iter().map(|s| at + s as u64).filter(|s| *s < end) {
                if start < cur.covered {
                    continue;
                }
                let (raw, ended) = read_message(source.as_ref(), start)?;
                cur.covered = start + raw.len().max(1) as u64;
                if let Some(f) = found(start, &raw, ended) {
                    pending.push(f);
                    cur.carved += 1;
                }
            }
            ctx.control().items_done(units(end - range.start()) - units(at - range.start()));
            at = end;
            cur.at = at;
            pending.commit(cur, false)?;
        }
        cur.range += 1;
        cur.at = 0;
    }
    Ok(())
}
