//! Volumes recovered after the evidence was added: deleted or lost partitions the deep scan
//! found. They are appended with new indexes, so stored hits and file rows of the volumes
//! already known keep pointing at the right volume.

use crate::Case;
use rusqlite::params;
use strata_kernel::{ByteRange, Error, EvidenceId, Result};
use strata_volume::{FsKind, Volume, VolumeOrigin, VolumeScanner};

/// Label prefix of volumes recovered from deleted or lost partitions.
pub const DELETED_PARTITION: &str = "deleted partition";

impl Case {
    /// Register a recovered volume (origin `Recovered`) and drop the cached layout so the next
    /// [`Case::layout`] parses it. Returns the stored volume, or the existing one at `range`.
    pub fn add_recovered_volume(&self, id: EvidenceId, range: ByteRange, fs: FsKind, note: &str) -> Result<Volume> {
        let record = self.record(id)?;
        if let Some(v) = record.volumes.iter().find(|v| v.range == range) {
            return Ok(v.clone());
        }
        if let Some(v) = record.volumes.iter().find(|v| v.range.intersect(&range).is_some()) {
            return Err(Error::Other(format!("{range} overlaps volume {} at {}", v.index, v.range)));
        }
        let index = record.volumes.iter().map(|v| v.index + 1).max().unwrap_or(0);
        let label = format!("{DELETED_PARTITION} P{index} {} ({note})", fs.name());
        let volume = Volume { index, range, fs, origin: VolumeOrigin::Recovered, label };
        self.with_write(|conn| {
            conn.execute(
                "INSERT INTO volumes (evidence_id, idx, start, len, fs, origin, label) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id.get(),
                    volume.index,
                    range.start() as i64,
                    range.len() as i64,
                    format!("{fs:?}"),
                    format!("{:?}", volume.origin),
                    volume.label
                ],
            )
        })?;
        self.forget_layout(id);
        Ok(volume)
    }

    /// [`Case::add_evidence`], then the deep partition sweep (cylinder starts and ends of old
    /// layouts) for volumes the quick sweep missed.
    pub fn add_evidence_deep(&self, location: &str) -> Result<crate::EvidenceRecord> {
        let record = self.add_evidence(location)?;
        let source = self.source(record.id)?;
        let found = VolumeScanner::default().with_deep_sweep(true).scan(source.as_ref());
        for v in found.iter().filter(|v| v.origin == VolumeOrigin::Recovered) {
            let known = self.record(record.id)?.volumes;
            if !known.iter().any(|k| k.range.intersect(&v.range).is_some()) {
                self.add_recovered_volume(record.id, v.range, v.fs, "deep sweep")?;
            }
        }
        self.record(record.id)
    }

    /// Store the file listing of one volume (content types already found are kept). Returns
    /// entries stored.
    pub fn index_volume_files(&self, id: EvidenceId, volume: u32) -> Result<usize> {
        let layout = self.layout(id)?;
        let Some((_, fs)) = layout.filesystems().find(|(v, _)| v.index == volume) else { return Ok(0) };
        self.write(|w| w.files(id, volume, fs.entries()))
    }
}
