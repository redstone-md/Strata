//! Import of an R-Studio scan file found next to an evidence image: verified volume
//! candidates join the case, everything else seeds the disk index.

use super::IndexService;
use serde::Serialize;
use std::path::Path;
use strata_index::scn::{ScnFile, ScnVolume};
use strata_index::{DEFAULT_BLOCK_SIZE, DiskIndex};
use strata_kernel::{ByteRange, EvidenceId, Result};
use strata_source::BlockSource;
use strata_volume::{BootSector, FsKind, Volume, VolumeOrigin};

/// What an import brought in.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScnImport {
    pub file: String,
    /// Candidates confirmed by our own boot-sector check.
    pub verified: usize,
    /// Verified candidates added to the case (the rest overlap known volumes).
    pub added: Vec<Volume>,
    pub signature_regions: usize,
    pub damage: Vec<String>,
}

impl IndexService<'_> {
    /// Look for `<image>.scn` beside the evidence file and import it. `Ok(None)` when there is
    /// none or the evidence is not a file.
    pub fn import_scn(&self, id: EvidenceId) -> Result<Option<ScnImport>> {
        let record = self.case.record(id)?;
        let Some(path) = ScnFile::beside(Path::new(&record.info.location)) else { return Ok(None) };
        let info = ScnFile::open(&path)?;
        let source = self.case.source(id)?;
        let len = source.len();
        let name = path.file_name().map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
        // Most supported candidates first, so they win where candidates overlap.
        let mut candidates: Vec<&ScnVolume> = info.recognized_volumes.iter().collect();
        candidates.sort_by(|a, b| b.confidence.total_cmp(&a.confidence).then(a.range.start().cmp(&b.range.start())));
        let verified: Vec<Volume> = candidates.into_iter().filter_map(|c| verify(source.as_ref(), c)).collect();
        let count = verified.len();
        let mut taken: Vec<ByteRange> = record.volumes.iter().map(|v| v.range).collect();
        let fresh: Vec<Volume> = verified
            .into_iter()
            .filter(|v| {
                let free = !taken.iter().any(|t| t.intersect(&v.range).is_some_and(|x| !x.is_empty()));
                if free {
                    taken.push(v.range);
                }
                free
            })
            .collect();
        let added = if fresh.is_empty() { Vec::new() } else { self.case.add_volumes(id, &fresh)? };
        let mut index = match self.load(id) {
            Some(i) if i.disk_len() == len && i.block_size() == DEFAULT_BLOCK_SIZE => (*i).clone(),
            _ => DiskIndex::new(len, DEFAULT_BLOCK_SIZE),
        };
        info.seed(&mut index, &format!("R-Studio scan: {name}"));
        self.save(id, &index)?;
        Ok(Some(ScnImport {
            file: name,
            verified: count,
            added,
            signature_regions: info.signature_regions.len(),
            damage: info.damage.iter().map(|d| d.note().to_string()).collect(),
        }))
    }
}

/// The candidate as a volume when the disk holds a matching boot sector (or ext superblock)
/// at its start; the length comes from that boot sector.
fn verify(disk: &dyn BlockSource, c: &ScnVolume) -> Option<Volume> {
    let start = c.range.start();
    let head = disk.read_vec(start, BootSector::HEAD_LEN).ok()?;
    let boot = BootSector::parse(&head).filter(|b| b.kind != FsKind::Unknown && same_family(c.fs, b.kind))?;
    let len = boot.declared_len.min(disk.len().saturating_sub(start));
    (len > 0).then(|| Volume {
        index: 0,
        range: ByteRange::new(start, len),
        fs: boot.kind,
        origin: VolumeOrigin::RStudioScan,
        label: format!("R-Studio {:?} @{start:#x}", boot.kind),
    })
}

fn family(fs: FsKind) -> u8 {
    match fs {
        FsKind::Ntfs => 1,
        FsKind::Fat12 | FsKind::Fat16 | FsKind::Fat32 => 2,
        FsKind::ExFat => 3,
        FsKind::Ext2 | FsKind::Ext3 | FsKind::Ext4 => 4,
        FsKind::Unknown => 0,
    }
}

/// R-Studio and our parser may name the FAT width or ext revision differently; an unknown
/// R-Studio type accepts whatever the disk shows.
fn same_family(claimed: FsKind, found: FsKind) -> bool {
    claimed == FsKind::Unknown || family(claimed) == family(found)
}
