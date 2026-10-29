//! After the deep scan: turn the partition structures it found into recovered volumes.
//!
//! Every stored `volume.partition` finding lists the volumes its structure implies. Each
//! reading is tried with the filesystem parsers; the one that recovers most entries wins,
//! and winners that do not overlap known volumes (or each other) are added to the case as
//! deleted partitions. Their files are indexed and stored hits re-attributed.

use strata_case::Case;
use strata_fs::open_filesystem;
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Result};
use strata_source::{BlockSource, SliceSource};
use strata_volume::{BootSector, CandidateResolver, FsKind, PartitionDetector, VolumeCandidate, gpt_candidates};
use std::sync::Arc;

#[derive(Debug, Default, Clone)]
pub struct PartitionReport {
    /// Structures the scan found.
    pub structures: usize,
    /// Volumes added: `(start, filesystem, entries)`.
    pub added: Vec<(u64, FsKind, usize)>,
}

impl PartitionReport {
    pub fn describe(&self) -> String {
        match self.added.len() {
            0 => format!("{} partition structures, no deleted partition beyond the known volumes", self.structures),
            n => format!("{n} deleted partitions recovered from {} partition structures", self.structures),
        }
    }
}

pub struct PartitionRecovery<'a> {
    case: &'a Case,
}

impl<'a> PartitionRecovery<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Filesystems to try when nothing at the volume start says which one it is.
    const BLIND: [FsKind; 2] = [FsKind::Ntfs, FsKind::Ext4];

    fn candidates(&self, id: EvidenceId, disk: &dyn BlockSource) -> Result<(usize, Vec<VolumeCandidate>)> {
        let q = strata_case::HitQuery { evidence: Some(id), categories: vec![HitCategory::Partition], ..Default::default() };
        let hits = self.case.hits(&q)?;
        let mut out = Vec::new();
        for h in hits.iter().filter(|h| h.hit.detector == PartitionDetector::ID) {
            out.extend(PartitionDetector::candidates_of(&h.hit));
            if let Some(header) = PartitionDetector::gpt_of(&h.hit) {
                out.extend(gpt_candidates(disk, &header));
            }
        }
        Ok((hits.len(), out))
    }

    /// Entries a parser recovers from the candidate, trying the filesystem its first sector
    /// names, then the one the structure implied, then the parsers that read backups.
    fn score(disk: &Arc<dyn BlockSource>, c: &VolumeCandidate) -> Option<(usize, FsKind)> {
        let slice: Arc<dyn BlockSource> = Arc::new(SliceSource::new(disk.clone(), c.range(), "candidate".to_string()));
        let named = slice.read_vec(0, BootSector::HEAD_LEN).ok().and_then(|h| BootSector::parse(&h)).map(|b| b.kind);
        let mut kinds: Vec<FsKind> = named.into_iter().chain([c.fs]).filter(|k| *k != FsKind::Unknown).collect();
        if kinds.is_empty() {
            kinds.extend(Self::BLIND);
        }
        kinds.dedup();
        kinds
            .into_iter()
            .filter_map(|k| open_filesystem(slice.clone(), k).ok().map(|fs| (fs.entries().len(), fs.kind())))
            .filter(|(n, _)| *n > 0)
            .max_by_key(|(n, _)| *n)
    }

    pub fn run(&self, id: EvidenceId) -> Result<PartitionReport> {
        let disk = self.case.source(id)?;
        let (structures, candidates) = self.candidates(id, disk.as_ref())?;
        let known = self.case.record(id)?.volumes.iter().map(|v| v.range).collect();
        let mut kinds = std::collections::HashMap::new();
        let accepted = CandidateResolver::new(known, disk.len()).resolve(candidates, |c| {
            let (n, kind) = Self::score(&disk, c)?;
            kinds.insert((c.start, c.len), (kind, n));
            Some(n)
        });
        let mut report = PartitionReport { structures, added: Vec::new() };
        let mut added = Vec::new();
        for c in accepted {
            let (fs, entries) = kinds.get(&(c.start, c.len)).copied().unwrap_or((c.fs, 0));
            added.push(self.case.add_recovered_volume(id, c.range(), fs, c.evidence.describe())?.index);
            report.added.push((c.start, fs, entries));
        }
        for volume in &added {
            self.case.index_volume_files(id, *volume)?;
        }
        if !added.is_empty() {
            self.case.reattribute(id)?;
        }
        Ok(report)
    }
}
