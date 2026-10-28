//! R-Studio disk image (`.rdr`).
//!
//! Layout (reverse-engineered from R-Studio 9 images):
//! every record starts with a 0x24-byte header
//! `magic 33 DA 54 D7 | u32 record_size | u32 kind | u32 0 | u32 FFFFFFFF | u64 a | u64 b`.
//! * file header at 0 (record_size 0x34, kind 1);
//! * data records, kind `0x18000020`: `a` = logical disk offset, `b` = payload length, payload
//!   (normally 256 KiB) follows the header;
//! * trailer index, kind `0x08000090`: `a` = disk size, followed by 12-byte entries
//!   `u64 file_offset | u32 record_size` for every data record.
//!
//! Blocks R-Studio could not read are simply absent; they read back as zeros and are reported
//! as damage. Images still being written (no trailer) are indexed by walking record headers.

use crate::file_io::read_full_at;
use crate::{BlockSource, SourceInfo, SourceKind};
use std::fs::File;
use std::path::{Path, PathBuf};
use strata_kernel::bytes::{u32_le, u64_le};
use strata_kernel::{ByteRange, Error, Result};

const MAGIC: [u8; 4] = [0x33, 0xDA, 0x54, 0xD7];
const HEADER_LEN: u64 = 0x24;
const KIND_DATA: u32 = 0x1800_0020;
const KIND_INDEX: u32 = 0x0800_0090;
const TRAILER_SEARCH: u64 = 64 << 20;
const CACHE_MAGIC: &[u8; 8] = b"STRDRIX1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block {
    logical: u64,
    file_data: u64,
    len: u64,
}

struct RecordHeader {
    size: u32,
    kind: u32,
    a: u64,
    b: u64,
}

impl RecordHeader {
    fn parse(raw: &[u8]) -> Option<Self> {
        if raw.get(..4)? != MAGIC {
            return None;
        }
        Some(Self { size: u32_le(raw, 4)?, kind: u32_le(raw, 8)?, a: u64_le(raw, 0x14)?, b: u64_le(raw, 0x1c)? })
    }
}

pub struct RdrImage {
    path: PathBuf,
    file: File,
    blocks: Vec<Block>,
    len: u64,
    gaps: Vec<ByteRange>,
}

impl RdrImage {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_cache(path, None)
    }

    /// `cache_dir` stores the block index so slow header walks happen once per image.
    pub fn open_with_cache(path: &Path, cache_dir: Option<&Path>) -> Result<Self> {
        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        let mut head = [0u8; 0x34];
        read_full_at(&file, 0, &mut head)?;
        let first = RecordHeader::parse(&head).ok_or_else(|| Error::format("not an R-Studio image"))?;

        let cache = cache_dir.map(|d| d.join(Self::cache_name(path, file_len)));
        let (blocks, disk_size) = match cache.as_deref().and_then(Self::load_cache) {
            Some(hit) => hit,
            None => {
                let built = Self::index_from_trailer(&file, file_len)
                    .unwrap_or_else(|| Self::index_by_walk(&file, u64::from(first.size), file_len));
                if let Some(c) = &cache {
                    Self::store_cache(c, &built.0, built.1);
                }
                built
            }
        };
        Ok(Self::assemble(path, file, blocks, disk_size))
    }

    fn assemble(path: &Path, file: File, mut blocks: Vec<Block>, disk_size: Option<u64>) -> Self {
        blocks.sort_by_key(|b| b.logical);
        let mapped_end = blocks.last().map_or(0, |b| b.logical + b.len);
        let len = disk_size.unwrap_or(mapped_end);
        let mut gaps = Vec::new();
        let mut cursor = 0;
        for b in &blocks {
            if b.logical > cursor {
                gaps.push(ByteRange::from_bounds(cursor, b.logical.min(len)));
            }
            cursor = cursor.max(b.logical + b.len);
        }
        if cursor < len {
            gaps.push(ByteRange::from_bounds(cursor, len));
        }
        Self { path: path.to_path_buf(), file, blocks, len, gaps: ByteRange::coalesce(gaps) }
    }

    fn index_from_trailer(file: &File, file_len: u64) -> Option<(Vec<Block>, Option<u64>)> {
        let start = file_len.saturating_sub(TRAILER_SEARCH);
        let mut tail = vec![0u8; (file_len - start) as usize];
        let n = read_full_at(file, start, &mut tail).ok()?;
        tail.truncate(n);
        let at = (0..tail.len().saturating_sub(HEADER_LEN as usize)).rev().find(|&i| {
            RecordHeader::parse(&tail[i..]).is_some_and(|h| h.kind == KIND_INDEX)
        })?;
        let trailer = RecordHeader::parse(&tail[at..])?;
        let entries = &tail[at + HEADER_LEN as usize..];
        let mut file_offsets: Vec<(u64, u32)> = Vec::new();
        for e in entries.chunks_exact(12) {
            let (off, size) = (u64_le(e, 0)?, u32_le(e, 8)?);
            if off >= file_len || u64::from(size) <= HEADER_LEN {
                break;
            }
            file_offsets.push((off, size));
        }
        if file_offsets.is_empty() {
            return None;
        }
        // Logical offsets live in each record header; the index only stores file positions.
        // Records are contiguous on disk in the common case, so verify a sample and fall back
        // to reading every header when the sample disagrees.
        let cumulative = Self::cumulative_blocks(&file_offsets);
        let sample_ok = Self::sample_matches(file, &cumulative);
        let blocks = if sample_ok { cumulative } else { Self::headers_at(file, &file_offsets) };
        Some((blocks, Some(trailer.a)))
    }

    fn cumulative_blocks(entries: &[(u64, u32)]) -> Vec<Block> {
        let mut logical = 0;
        entries
            .iter()
            .map(|&(off, size)| {
                let len = u64::from(size) - HEADER_LEN;
                let b = Block { logical, file_data: off + HEADER_LEN, len };
                logical += len;
                b
            })
            .collect()
    }

    fn sample_matches(file: &File, blocks: &[Block]) -> bool {
        let step = (blocks.len() / 64).max(1);
        blocks.iter().step_by(step).chain(blocks.last()).all(|b| {
            let mut raw = [0u8; HEADER_LEN as usize];
            read_full_at(file, b.file_data - HEADER_LEN, &mut raw).is_ok()
                && RecordHeader::parse(&raw).is_some_and(|h| h.kind == KIND_DATA && h.a == b.logical && h.b == b.len)
        })
    }

    fn headers_at(file: &File, entries: &[(u64, u32)]) -> Vec<Block> {
        entries
            .iter()
            .filter_map(|&(off, _)| {
                let mut raw = [0u8; HEADER_LEN as usize];
                read_full_at(file, off, &mut raw).ok()?;
                let h = RecordHeader::parse(&raw).filter(|h| h.kind == KIND_DATA)?;
                Some(Block { logical: h.a, file_data: off + HEADER_LEN, len: h.b })
            })
            .collect()
    }

    /// Sequential header walk; resynchronises on the magic if a record is damaged.
    fn index_by_walk(file: &File, mut pos: u64, file_len: u64) -> (Vec<Block>, Option<u64>) {
        let mut blocks = Vec::new();
        let mut disk_size = None;
        let mut raw = [0u8; HEADER_LEN as usize];
        while pos + HEADER_LEN <= file_len {
            if read_full_at(file, pos, &mut raw).is_err() {
                break;
            }
            match RecordHeader::parse(&raw) {
                Some(h) if h.kind == KIND_DATA && h.b > 0 && pos + HEADER_LEN + h.b <= file_len => {
                    blocks.push(Block { logical: h.a, file_data: pos + HEADER_LEN, len: h.b });
                    pos += HEADER_LEN + h.b;
                }
                Some(h) if h.kind == KIND_INDEX => {
                    disk_size = Some(h.a);
                    break;
                }
                Some(h) if u64::from(h.size) >= HEADER_LEN => pos += u64::from(h.size),
                _ => match Self::resync(file, pos + 1, file_len) {
                    Some(next) => pos = next,
                    None => break,
                },
            }
        }
        (blocks, disk_size)
    }

    fn resync(file: &File, from: u64, file_len: u64) -> Option<u64> {
        let mut buf = vec![0u8; 1 << 20];
        let mut pos = from;
        while pos < file_len {
            let n = read_full_at(file, pos, &mut buf).ok()?;
            if n < MAGIC.len() {
                return None;
            }
            if let Some(i) = buf[..n].windows(4).position(|w| w == MAGIC) {
                return Some(pos + i as u64);
            }
            pos += (n - 3) as u64;
        }
        None
    }

    fn cache_name(path: &Path, file_len: u64) -> String {
        let stem = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        format!("{stem}.{file_len}.rdrindex")
    }

    fn load_cache(path: &Path) -> Option<(Vec<Block>, Option<u64>)> {
        let data = std::fs::read(path).ok()?;
        if data.get(..8)? != CACHE_MAGIC {
            return None;
        }
        let disk = u64_le(&data, 8)?;
        let blocks = data[16..]
            .chunks_exact(24)
            .map(|c| Some(Block { logical: u64_le(c, 0)?, file_data: u64_le(c, 8)?, len: u64_le(c, 16)? }))
            .collect::<Option<Vec<_>>>()?;
        Some((blocks, (disk != 0).then_some(disk)))
    }

    fn store_cache(path: &Path, blocks: &[Block], disk_size: Option<u64>) {
        let mut out = Vec::with_capacity(16 + blocks.len() * 24);
        out.extend_from_slice(CACHE_MAGIC);
        out.extend_from_slice(&disk_size.unwrap_or(0).to_le_bytes());
        for b in blocks {
            for v in [b.logical, b.file_data, b.len] {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        // A cache is an optimisation; failure to write it must not fail opening evidence.
        let _ = std::fs::write(path, out);
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    fn block_index(&self, offset: u64) -> Option<usize> {
        let i = self.blocks.partition_point(|b| b.logical + b.len <= offset);
        self.blocks.get(i).filter(|b| b.logical <= offset).map(|_| i)
    }
}

impl BlockSource for RdrImage {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            kind: SourceKind::RStudioImage,
            label: self.path.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            location: self.path.display().to_string(),
            len: self.len,
            sector_size: 512,
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
        let mut done = 0;
        while done < want {
            let pos = offset + done as u64;
            let out = &mut buf[done..want];
            match self.block_index(pos) {
                Some(i) => {
                    let b = self.blocks[i];
                    let within = pos - b.logical;
                    let n = ((b.len - within) as usize).min(out.len());
                    let got = read_full_at(&self.file, b.file_data + within, &mut out[..n])?;
                    out[got..n].fill(0);
                    done += n;
                }
                None => {
                    let next = self.blocks.get(self.blocks.partition_point(|b| b.logical <= pos));
                    let gap_end = next.map_or(self.len, |b| b.logical);
                    let n = ((gap_end - pos) as usize).min(out.len());
                    out[..n].fill(0);
                    done += n.max(1);
                }
            }
        }
        Ok(want)
    }

    fn damage(&self) -> Vec<ByteRange> {
        self.gaps.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn header(size: u32, kind: u32, a: u64, b: u64) -> Vec<u8> {
        let mut h = MAGIC.to_vec();
        for v in [size, kind, 0, u32::MAX] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        h.extend_from_slice(&a.to_le_bytes());
        h.extend_from_slice(&b.to_le_bytes());
        h
    }

    /// Synthetic image: blocks at logical 0 and 16 (8 bytes each), gap 8..16, disk size 32.
    fn synthetic(with_trailer: bool) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.rdr");
        let mut f = File::create(&path).unwrap();
        let mut body = header(0x34, 1, 0, 0);
        body.resize(0x34, 0);
        let mut entries = Vec::new();
        for (logical, fill) in [(0u64, b'A'), (16, b'B')] {
            entries.push((body.len() as u64, (HEADER_LEN + 8) as u32));
            body.extend(header((HEADER_LEN + 8) as u32, KIND_DATA, logical, 8));
            body.extend([fill; 8]);
        }
        if with_trailer {
            body.extend(header(0, KIND_INDEX, 32, 0));
            for (off, size) in entries {
                body.extend(off.to_le_bytes());
                body.extend(size.to_le_bytes());
            }
        }
        f.write_all(&body).unwrap();
        (dir, path)
    }

    #[test]
    fn reads_blocks_and_zero_fills_gaps() {
        for trailer in [true, false] {
            let (_d, path) = synthetic(trailer);
            let img = RdrImage::open(&path).unwrap();
            let data = img.read_vec(4, 16).unwrap();
            assert_eq!(&data[..4], b"AAAA");
            assert_eq!(&data[4..12], &[0u8; 8]);
            assert_eq!(&data[12..], b"BBBB");
            assert!(img.damage().contains(&ByteRange::new(8, 8)));
        }
    }

    #[test]
    fn trailer_gives_disk_size_and_cache_roundtrips() {
        let (dir, path) = synthetic(true);
        let img = RdrImage::open_with_cache(&path, Some(dir.path())).unwrap();
        assert_eq!(img.len(), 32);
        assert_eq!(img.damage(), vec![ByteRange::new(8, 8), ByteRange::new(24, 8)]);
        let again = RdrImage::open_with_cache(&path, Some(dir.path())).unwrap();
        assert_eq!(again.block_count(), 2);
        assert_eq!(again.read_vec(16, 2).unwrap(), b"BB");
    }
}
