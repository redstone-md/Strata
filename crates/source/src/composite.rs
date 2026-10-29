//! Two or more images of the same physical medium merged into one better copy.
//!
//! Typical case: a failing disk imaged twice (or with different tools) — each pass leaves
//! different unreadable sectors. Reads go to the primary; ranges the primary marks as damaged
//! are served by the first other source that has them.

use crate::{BlockSource, SourceInfo};
use std::sync::Arc;
use strata_kernel::{ByteRange, Result};

pub struct CompositeSource {
    layers: Vec<Arc<dyn BlockSource>>,
    damage: Vec<Vec<ByteRange>>,
}

impl CompositeSource {
    /// `layers[0]` is the primary. All layers must describe the same medium (see
    /// [`CompositeSource::same_medium`]).
    pub fn new(layers: Vec<Arc<dyn BlockSource>>) -> Self {
        let damage = layers.iter().map(|l| l.damage()).collect();
        Self { layers, damage }
    }

    /// Cheap identity check: equal length and identical content at sampled offsets that are
    /// readable in both sources. Needs at least `min_matches` comparable non-zero samples.
    pub fn same_medium(a: &dyn BlockSource, b: &dyn BlockSource, min_matches: usize) -> bool {
        if a.len() != b.len() || a.len() < 4096 {
            return false;
        }
        let (da, db) = (a.damage(), b.damage());
        let samples = 64u64;
        let step = (a.len() / samples).max(4096) / 4096 * 4096;
        let mut matches = 0;
        for i in 0..samples {
            let off = i * step;
            let probe = ByteRange::new(off, 4096);
            if probe.end() > a.len() || probe.covered_by(&da) > 0 || probe.covered_by(&db) > 0 {
                continue;
            }
            let (Ok(x), Ok(y)) = (a.read_vec(off, 4096), b.read_vec(off, 4096)) else { continue };
            if x != y {
                return false;
            }
            if x.iter().any(|b| *b != 0) {
                matches += 1;
            }
        }
        matches >= min_matches
    }

    /// Bytes the primary lacks that another layer provides.
    pub fn recovered_bytes(&self) -> u64 {
        let primary = &self.damage[0];
        primary.iter().map(|r| r.len() - Self::still_missing(r, &self.damage[1..]).iter().map(|m| m.len()).sum::<u64>()).sum()
    }

    /// Parts of `range` that every layer in `others` reports as damaged.
    fn still_missing(range: &ByteRange, others: &[Vec<ByteRange>]) -> Vec<ByteRange> {
        others.iter().fold(vec![*range], |missing, layer| {
            missing.iter().flat_map(|m| layer.iter().filter_map(|d| d.intersect(m))).collect()
        })
    }

    fn layer_for(&self, range: &ByteRange) -> Option<usize> {
        self.damage.iter().position(|d| range.covered_by(d) == 0)
    }
}

impl BlockSource for CompositeSource {
    fn info(&self) -> SourceInfo {
        let p = self.layers[0].info();
        SourceInfo {
            kind: p.kind,
            label: format!("{} (+{} merged)", p.label, self.layers.len() - 1),
            location: self.layers.iter().map(|l| l.info().location).collect::<Vec<_>>().join(" | "),
            len: p.len,
            sector_size: p.sector_size,
        }
    }

    fn len(&self) -> u64 {
        self.layers[0].len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let n = self.layers[0].read_at(offset, buf)?;
        let window = ByteRange::new(offset, n as u64);
        for bad in self.damage[0].iter().filter_map(|d| d.intersect(&window)) {
            // Fill sector by sector so partially covered ranges still benefit.
            let mut pos = bad.start();
            while pos < bad.end() {
                let piece = ByteRange::from_bounds(pos, (pos + 512).min(bad.end()));
                if let Some(layer) = self.layer_for(&piece).filter(|l| *l > 0) {
                    let dst = &mut buf[(piece.start() - offset) as usize..(piece.end() - offset) as usize];
                    self.layers[layer].read_at(piece.start(), dst)?;
                }
                pos = piece.end();
            }
        }
        Ok(n)
    }

    fn damage(&self) -> Vec<ByteRange> {
        ByteRange::coalesce(self.damage[0].iter().flat_map(|r| Self::still_missing(r, &self.damage[1..])).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceKind;

    struct Mem(Vec<u8>, Vec<ByteRange>);
    impl BlockSource for Mem {
        fn info(&self) -> SourceInfo {
            SourceInfo { kind: SourceKind::RawImage, label: "m".into(), location: "m".into(), len: self.len(), sector_size: 512 }
        }
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
            let s = offset as usize;
            let n = buf.len().min(self.0.len() - s);
            buf[..n].copy_from_slice(&self.0[s..s + n]);
            for d in &self.1 {
                if let Some(x) = d.intersect(&ByteRange::new(offset, n as u64)) {
                    buf[(x.start() - offset) as usize..(x.end() - offset) as usize].fill(0);
                }
            }
            Ok(n)
        }
        fn damage(&self) -> Vec<ByteRange> {
            self.1.clone()
        }
    }

    #[test]
    fn fills_primary_holes_from_second_image() {
        let disk: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8 + 1).collect();
        let a = Arc::new(Mem(disk.clone(), vec![ByteRange::new(4096, 1024), ByteRange::new(8192, 512)]));
        let b = Arc::new(Mem(disk.clone(), vec![ByteRange::new(8192, 512)]));
        assert!(CompositeSource::same_medium(a.as_ref(), b.as_ref(), 8));
        let c = CompositeSource::new(vec![a, b]);
        assert_eq!(c.read_vec(4000, 2000).unwrap(), disk[4000..6000]);
        assert_eq!(c.damage(), vec![ByteRange::new(8192, 512)]);
        assert_eq!(c.recovered_bytes(), 1024);
    }
}
