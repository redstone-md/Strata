//! Copy selected files and folders (live, deleted, orphaned) out of the evidence to
//! `<dest>/<disk>/<volume>/<path>`, through each filesystem's extent reader.

use super::writer::{Item, RecoveryWriter};
use std::collections::HashSet;
use strata_case::Case;
use strata_engine::ScanControl;
use strata_fs::{EntryState, FileEntry, FileId, FileSystem};
use strata_kernel::{ByteRange, EvidenceId, Result};
use strata_volume::{Volume, VolumeOrigin};

#[derive(Debug, Default, Clone, Copy)]
pub struct RecoverySummary {
    pub files: usize,
    pub partial: usize,
    pub failed: usize,
    pub bytes: u64,
}

impl RecoverySummary {
    pub fn describe(&self) -> String {
        let mut s = format!("{} files recovered, {} partial", self.files, self.partial);
        if self.failed > 0 {
            s += &format!(", {} could not be written", self.failed);
        }
        s
    }
}

/// Folder name of a volume under the disk folder.
pub fn volume_folder(v: &Volume) -> String {
    let deleted = if v.origin == VolumeOrigin::Recovered { " deleted partition" } else { "" };
    format!("V{} {}{deleted}", v.index, v.fs.name())
}

/// State word used in logs and badges.
pub fn state_word(state: EntryState) -> &'static str {
    match state {
        EntryState::Allocated => "live",
        EntryState::Deleted => "deleted",
        EntryState::Orphan => "orphan",
    }
}

/// What can still be trusted of an entry's content.
pub fn assess(e: &FileEntry, free: &[ByteRange]) -> Item {
    let mut damage: Vec<String> = e.damage.iter().map(|d| d.note().to_string()).collect();
    let mut lost = 0u64;
    if e.is_deleted() && e.resident.is_none() {
        let reused: u64 = e
            .extents
            .iter()
            .filter_map(|x| x.volume_offset.map(|v| ByteRange::new(v, x.len)))
            .map(|r| r.len() - r.covered_by(free))
            .sum();
        if reused > 0 {
            damage.push(format!("{reused} bytes of its clusters are in use by other data"));
        }
        lost = reused;
    }
    Item { source_path: e.path.clone(), state: state_word(e.state).into(), size: e.size, intact: e.size.saturating_sub(lost), damage }
}

pub struct FileRecovery<'a> {
    case: &'a Case,
}

impl<'a> FileRecovery<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Files under the selected entries (folders expand to everything below them).
    fn expand(fs: &dyn FileSystem, selection: &[usize]) -> Vec<usize> {
        let mut seen = HashSet::new();
        let mut stack: Vec<usize> = selection.to_vec();
        let mut out = Vec::new();
        while let Some(i) = stack.pop() {
            if !seen.insert(i) {
                continue;
            }
            let Some(e) = fs.entry(FileId::new(i)) else { continue };
            out.push(i);
            if e.is_dir {
                stack.extend(fs.children(FileId::new(i)).into_iter().map(FileId::index));
            }
        }
        out.sort_unstable();
        out
    }

    /// Recover `selection` (entry indexes of one volume) into `dest`.
    pub fn run(&self, id: EvidenceId, volume: u32, selection: &[usize], dest: &std::path::Path, control: &ScanControl) -> Result<RecoverySummary> {
        let record = self.case.record(id)?;
        let locations: Vec<String> = self.case.evidence()?.into_iter().map(|e| e.info.location).collect();
        let mut writer = RecoveryWriter::open(dest, &locations)?;
        let layout = self.case.layout(id)?;
        let (vol, fs) = layout.filesystem(volume).ok_or_else(|| strata_kernel::Error::Other(format!("volume {volume} did not parse")))?;
        let free = fs.unallocated();
        let base = vec![record.info.label.clone(), volume_folder(vol)];
        let items = Self::expand(fs, selection);
        control.begin_items(items.len() as u64);
        let mut summary = RecoverySummary::default();
        for i in items {
            if control.is_cancelled() {
                break;
            }
            control.item_done();
            let Some(e) = fs.entry(FileId::new(i)) else { continue };
            let mut components = base.clone();
            components.extend(e.path.split('/').filter(|c| !c.is_empty()).map(str::to_string));
            if e.is_dir {
                writer.directory(&components)?;
                continue;
            }
            let item = assess(e, &free);
            let mut read = |off: u64, buf: &mut [u8]| fs.read(FileId::new(i), off, buf);
            match writer.write(&components, &item, &mut read) {
                Ok(r) => {
                    summary.files += 1;
                    summary.partial += usize::from(r.partial);
                    summary.bytes += r.bytes_written;
                }
                Err(_) => summary.failed += 1,
            }
        }
        writer.finish()?;
        Ok(summary)
    }
}
