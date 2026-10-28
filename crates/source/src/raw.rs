//! Raw (dd) images, including split sets `name.001, name.002, ...`.

use crate::file_io::read_full_at;
use crate::{BlockSource, SourceInfo, SourceKind};
use std::fs::File;
use std::path::{Path, PathBuf};
use strata_kernel::{ByteRange, Error, Result};

struct Segment {
    file: File,
    start: u64,
    len: u64,
}

pub struct RawImage {
    path: PathBuf,
    segments: Vec<Segment>,
    len: u64,
    damage: Vec<ByteRange>,
}

impl RawImage {
    pub fn open(path: &Path) -> Result<Self> {
        let parts = Self::segment_paths(path);
        let mut segments = Vec::with_capacity(parts.len());
        let mut start = 0;
        for part in parts {
            let file = File::open(&part)?;
            let len = file.metadata()?.len();
            segments.push(Segment { file, start, len });
            start += len;
        }
        let damage = Self::load_bad_map(path);
        Ok(Self { path: path.to_path_buf(), segments, len: start, damage })
    }

    /// `x.001` expands to all consecutive numbered parts; anything else is a single file.
    fn segment_paths(path: &Path) -> Vec<PathBuf> {
        let is_split = path.extension().and_then(|e| e.to_str()) == Some("001");
        if !is_split {
            return vec![path.to_path_buf()];
        }
        (1..10_000)
            .map(|i| path.with_extension(format!("{i:03}")))
            .take_while(|p| p.exists())
            .collect()
    }

    /// Imaging tools in the old workflow wrote `<image>.map.jsonl` with unreadable ranges
    /// (`{"offset":..,"length":..}` per line). Honour it so zero-filled holes are flagged.
    fn load_bad_map(path: &Path) -> Vec<ByteRange> {
        let mut map = path.as_os_str().to_owned();
        map.push(".map.jsonl");
        let Ok(text) = std::fs::read_to_string(PathBuf::from(map)) else {
            return Vec::new();
        };
        let ranges = text
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| Some(ByteRange::new(v["offset"].as_u64()?, v["length"].as_u64()?)))
            .collect();
        ByteRange::coalesce(ranges)
    }
}

impl BlockSource for RawImage {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            kind: SourceKind::RawImage,
            label: self.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
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
            let seg = self
                .segments
                .iter()
                .find(|s| pos >= s.start && pos < s.start + s.len)
                .ok_or(Error::OutOfRange { offset: pos, len: self.len })?;
            let in_seg = (seg.start + seg.len - pos).min((want - done) as u64) as usize;
            let n = read_full_at(&seg.file, pos - seg.start, &mut buf[done..done + in_seg])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    fn damage(&self) -> Vec<ByteRange> {
        self.damage.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn split_image_reads_across_segments() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("disk");
        File::create(base.with_extension("001")).unwrap().write_all(b"hello ").unwrap();
        File::create(base.with_extension("002")).unwrap().write_all(b"world").unwrap();
        let img = RawImage::open(&base.with_extension("001")).unwrap();
        assert_eq!(img.len(), 11);
        assert_eq!(img.read_vec(3, 6).unwrap(), b"lo wor");
        assert_eq!(img.read_vec(9, 10).unwrap(), b"ld");
    }
}
