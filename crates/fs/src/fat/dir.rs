//! Directory content: 32-byte slots into named records, long names reassembled and checked.

use super::dirent::{ENTRY_SIZE, LfnSlot, ShortEntry, is_lfn};
pub(super) use crate::dirbuf::DirBuffer;
use strata_kernel::{ByteRange, Damage};

/// One file or directory found in a directory.
pub(super) struct DirRecord {
    name: String,
    short: ShortEntry,
    offset: u64,
    damage: Vec<Damage>,
}

impl DirRecord {
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn short(&self) -> &ShortEntry {
        &self.short
    }

    /// Volume byte offset of the 8.3 entry.
    pub(super) fn offset(&self) -> u64 {
        self.offset
    }

    pub(super) fn take_damage(&mut self) -> Vec<Damage> {
        std::mem::take(&mut self.damage)
    }
}

/// Parse a directory. Volume labels, `.`/`..` and implausible (garbage) slots are skipped.
pub(super) fn parse(buf: &DirBuffer) -> Vec<DirRecord> {
    let mut out = Vec::new();
    let mut pending: Vec<LfnSlot> = Vec::new();
    for (i, e) in buf.bytes().as_chunks::<ENTRY_SIZE>().0.iter().enumerate() {
        if e[0] == 0 {
            break;
        }
        if is_lfn(e) {
            if let Some(slot) = LfnSlot::parse(e) {
                pending.push(slot);
            }
            continue;
        }
        let slots = std::mem::take(&mut pending);
        let Some(short) = ShortEntry::parse(e) else { continue };
        if short.is_volume_label() || short.is_dot() || !short.is_plausible() {
            continue;
        }
        let offset = buf.volume_offset(i * ENTRY_SIZE);
        out.push(record(short, &slots, offset));
    }
    out
}

fn record(short: ShortEntry, slots: &[LfnSlot], offset: u64) -> DirRecord {
    let mut damage = Vec::new();
    let name = if short.is_deleted() {
        match deleted_long_name(&short, slots) {
            Some(name) => name,
            None => short.display_name(Some(b'_')),
        }
    } else {
        match live_long_name(&short, slots) {
            Some(name) => name,
            None => {
                if slots.iter().any(|s| !s.is_deleted()) {
                    let at = ByteRange::new(offset, ENTRY_SIZE as u64);
                    damage.push(Damage::corrupt(at, "long name does not match its 8.3 entry; using 8.3 name"));
                }
                short.display_name(None)
            }
        }
    };
    DirRecord { name, short, offset, damage }
}

/// Slots must run N|0x40, N-1, ..., 1 and carry the 8.3 name's checksum.
fn live_long_name(short: &ShortEntry, slots: &[LfnSlot]) -> Option<String> {
    let n = slots.len();
    let sum = short.checksum();
    let ordered = slots.iter().enumerate().all(|(i, s)| {
        !s.is_deleted() && usize::from(s.sequence()) == n - i && s.checksum() == sum && s.is_last() == (i == 0)
    });
    (n > 0 && ordered).then(|| LfnSlot::assemble(slots)).filter(|s| !s.is_empty())
}

/// Deleted slots lose their sequence byte (and the 8.3 entry its first byte). Accept them when
/// all share one checksum and some first byte makes the 8.3 name match it.
fn deleted_long_name(short: &ShortEntry, slots: &[LfnSlot]) -> Option<String> {
    let sum = slots.first()?.checksum();
    if !slots.iter().all(|s| s.is_deleted() && s.checksum() == sum) {
        return None;
    }
    let name = LfnSlot::assemble(slots);
    let guess = name.chars().next().filter(char::is_ascii).map(|c| c.to_ascii_uppercase() as u8);
    guess
        .into_iter()
        .chain(0x21..=0xFF)
        .find(|b| *b != super::dirent::DELETED_MARK && short.checksum_with_first(*b) == sum)?;
    (!name.is_empty()).then_some(name)
}
