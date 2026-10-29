//! EnCase / Expert Witness Format images, EWF version 1 (`.E01`, SMART `.s01`).
//!
//! A set is split into segment files (`.E01`, `.E02` … `.E99`, `.EAA` …). Each starts with a
//! 13-byte file header (`EVF 09 0D 0A FF 00`, `u8 1`, `u16 segment number`, `u16 0`) followed by
//! a chain of sections (see [`section`]). The media is cut into fixed-size chunks, listed in
//! `table` sections (backed up by `table2`) and stored zlib-compressed or raw with an Adler-32.
//!
//! Damage: sectors the acquiring tool could not read (`error2`), chunks missing from every table,
//! and chunks that fail to decode all read back as zeros and are reported by
//! [`BlockSource::damage`]. Decode failures are found lazily, on first read of the chunk.
//! EWF2 (`.Ex01`) and logical evidence (`.L01`) are recognised and rejected with a clear error.

mod chunk;
mod layout;
mod metadata;
mod section;
mod segment;
mod table;
#[cfg(test)]
mod tests;

pub use metadata::StoredHashes;

use crate::file_io::read_full_at;
use crate::{BlockSource, SourceInfo, SourceKind};
use chunk::ChunkCache;
use layout::{Geometry, Layout};
use parking_lot::Mutex;
use segment::SegmentFile;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use strata_kernel::{ByteRange, Error, Result};

const CACHED_CHUNKS: usize = 64;

pub struct EwfImage {
    path: PathBuf,
    segments: Vec<SegmentFile>,
    layout: Layout,
    geometry: Geometry,
    len: u64,
    known_damage: Vec<ByteRange>,
    failed_chunks: Mutex<BTreeSet<u64>>,
    cache: ChunkCache,
}

impl EwfImage {
    /// Open the set `path` belongs to (normally the `.E01`; later segments are found by name).
    pub fn open(path: &Path) -> Result<Self> {
        let segments = segment::segment_paths(path)
            .iter()
            .map(|p| SegmentFile::open(p))
            .collect::<Result<Vec<_>>>()?;
        let first = segments.first().ok_or_else(|| Error::format("no EWF segment files"))?;
        let mut head = [0u8; 8];
        let n = read_full_at(first.file(), 0, &mut head)?;
        segment::check_signature(&head[..n])?;

        let layout = Layout::read(&segments);
        if layout.geometry.is_none() && layout.tables.is_empty() {
            return Err(Error::format("EWF image has neither a volume section nor a chunk table"));
        }
        let geometry = layout.geometry.unwrap_or(Geometry::FALLBACK);
        let len = geometry.media_len(layout.chunks_found());
        let known_damage = Self::known_damage(&layout, &geometry, len);
        Ok(Self {
            path: path.to_path_buf(),
            segments,
            layout,
            geometry,
            len,
            known_damage,
            failed_chunks: Mutex::new(BTreeSet::new()),
            cache: ChunkCache::new(CACHED_CHUNKS),
        })
    }

    /// Acquisition read errors plus the tail no table covers.
    fn known_damage(layout: &Layout, geometry: &Geometry, len: u64) -> Vec<ByteRange> {
        let bps = u64::from(geometry.bytes_per_sector);
        let mut ranges: Vec<ByteRange> = layout
            .read_errors
            .iter()
            .map(|&(first, count)| ByteRange::new(first.saturating_mul(bps), count.saturating_mul(bps)))
            .filter_map(|r| r.intersect(&ByteRange::new(0, len)))
            .collect();
        let mapped = layout.chunks_found().saturating_mul(geometry.chunk_size);
        if mapped < len {
            ranges.push(ByteRange::from_bounds(mapped, len));
        }
        ByteRange::coalesce(ranges)
    }

    /// Case metadata from `header2`/`header`: `case_number`, `evidence_number`, `description`,
    /// `examiner`, `notes`, `acquired`, … (unknown keys keep their EWF abbreviation).
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.layout.metadata
    }

    /// MD5/SHA-1 of the media as recorded by the acquiring tool.
    pub fn stored_hashes(&self) -> &StoredHashes {
        &self.layout.hashes
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn chunk_size(&self) -> u64 {
        self.geometry.chunk_size
    }

    pub fn chunk_count(&self) -> u64 {
        self.layout.chunks_found()
    }

    /// How many damaged `table` sections were replaced by their `table2` backup.
    pub fn table_fallbacks(&self) -> usize {
        self.layout.table_fallbacks
    }

    /// Decoded chunk `index`; empty when absent or undecodable (reads back as zeros).
    fn chunk(&self, index: u64) -> Arc<[u8]> {
        if let Some(hit) = self.cache.get(index) {
            return hit;
        }
        let at = self.layout.tables.partition_point(|t| t.end() <= index);
        let Some(location) = self.layout.tables.get(at).and_then(|t| t.locate(index)) else {
            return Arc::from(Vec::new());
        };
        let chunk_size = self.geometry.chunk_size as usize;
        let expected = (self.len - index * self.geometry.chunk_size).min(self.geometry.chunk_size) as usize;
        let decoded = self
            .segments
            .get(location.segment)
            .and_then(|s| chunk::decode(s.file(), &location, chunk_size, expected));
        let data: Arc<[u8]> = match decoded {
            Some(d) => Arc::from(d),
            None => {
                self.failed_chunks.lock().insert(index);
                Arc::from(Vec::new())
            }
        };
        self.cache.put(index, data.clone());
        data
    }
}

impl BlockSource for EwfImage {
    fn info(&self) -> SourceInfo {
        let stem = self.path.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let label = match self.layout.metadata.get("case_number") {
            Some(case) => format!("{stem} (case {case})"),
            None => stem,
        };
        SourceInfo {
            kind: SourceKind::EwfImage,
            label,
            location: self.path.display().to_string(),
            len: self.len,
            sector_size: self.geometry.bytes_per_sector,
        }
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let want = buf.len().min((self.len - offset) as usize);
        let size = self.geometry.chunk_size;
        let mut done = 0;
        while done < want {
            let pos = offset + done as u64;
            let within = (pos % size) as usize;
            let n = (size as usize - within).min(want - done);
            let out = &mut buf[done..done + n];
            let data = self.chunk(pos / size);
            let have = data.get(within..).map_or(0, |d| d.len().min(n));
            out[..have].copy_from_slice(&data[within..within + have]);
            out[have..].fill(0);
            done += n;
        }
        Ok(want)
    }

    fn damage(&self) -> Vec<ByteRange> {
        let size = self.geometry.chunk_size;
        let mut ranges = self.known_damage.clone();
        ranges.extend(self.failed_chunks.lock().iter().map(|i| {
            let start = i * size;
            ByteRange::from_bounds(start, (start + size).min(self.len))
        }));
        ByteRange::coalesce(ranges)
    }
}
