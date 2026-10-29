//! The file allocation table: cluster links, chains with loop protection, free clusters.
//! Shared by FAT12/16/32 and exFAT.

use crate::alloc::ClusterMap;
use std::collections::HashSet;
use strata_kernel::{ByteRange, Damage, DamageKind};
use strata_source::BlockSource;

/// Entry width and end-of-chain conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FatWidth {
    Fat12,
    Fat16,
    /// 28 significant bits.
    Fat32,
    /// Full 32 bits.
    ExFat,
}

impl FatWidth {
    fn bits(self) -> u64 {
        match self {
            Self::Fat12 => 12,
            Self::Fat16 => 16,
            Self::Fat32 | Self::ExFat => 32,
        }
    }

    /// (bad cluster mark, first end-of-chain value).
    fn marks(self) -> (u32, u32) {
        match self {
            Self::Fat12 => (0xFF7, 0xFF8),
            Self::Fat16 => (0xFFF7, 0xFFF8),
            Self::Fat32 => (0x0FFF_FFF7, 0x0FFF_FFF8),
            Self::ExFat => (0xFFFF_FFF7, 0xFFFF_FFF8),
        }
    }
}

/// Where the FAT copies are: the first offset is the copy to trust, the next one the backup.
pub(crate) struct FatLayout {
    width: FatWidth,
    copies: Vec<u64>,
    copy_bytes: u64,
    max_cluster: u32,
}

impl FatLayout {
    pub(crate) fn new(width: FatWidth, copies: Vec<u64>, copy_bytes: u64, max_cluster: u32) -> Self {
        Self { width, copies, copy_bytes, max_cluster }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Link {
    Free,
    Next(u32),
    End,
    Bad,
    /// Reserved or out-of-range value: the entry itself is damaged.
    Invalid,
}

/// Why a chain stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainEnd {
    Eoc,
    Limit,
    Broken(&'static str),
}

pub(crate) struct Chain {
    clusters: Vec<u32>,
    end: ChainEnd,
}

impl Chain {
    pub(crate) fn clusters(&self) -> &[u32] {
        &self.clusters
    }

    pub(crate) fn end(&self) -> ChainEnd {
        self.end
    }
}

pub(crate) struct FatTable {
    entries: Vec<u32>,
    width: FatWidth,
    max_cluster: u32,
}

impl FatTable {
    /// Load FAT copy 1; entries that look damaged (invalid values, unreadable sectors) are
    /// taken from copy 2 when that one has a sane value.
    pub(crate) fn load(source: &dyn BlockSource, layout: &FatLayout) -> (Self, Vec<Damage>) {
        let width = layout.width;
        let count = layout.max_cluster as usize + 1;
        let bytes = ((count as u64 * width.bits()).div_ceil(8)).min(layout.copy_bytes);
        let read = |copy: usize| -> Option<Vec<u8>> { source.read_vec(*layout.copies.get(copy)?, bytes as usize).ok() };
        let mut table = Self { entries: Vec::new(), width, max_cluster: layout.max_cluster };
        let mut damage = Vec::new();
        let Some(primary) = read(0) else {
            damage.push(Damage::new(DamageKind::Unreadable, None, "FAT copy 1 unreadable"));
            return (table, damage);
        };
        table.entries = table.decode(&primary, count);
        let fat1 = ByteRange::new(layout.copies.first().copied().unwrap_or(0), bytes);
        let unreadable: Vec<ByteRange> = source.damage().iter().filter_map(|d| d.intersect(&fat1)).collect();
        let suspect: Vec<usize> = (2..count)
            .filter(|&i| {
                let at = fat1.start() + (i as u64 * width.bits()) / 8;
                table.classify(table.entries[i]) == Link::Invalid || unreadable.iter().any(|r| r.contains(at))
            })
            .collect();
        if suspect.is_empty() {
            return (table, damage);
        }
        let backup = read(1).map(|b| table.decode(&b, count));
        let mut repaired = 0;
        if let Some(backup) = &backup {
            for &i in &suspect {
                if let Some(&v) = backup.get(i).filter(|v| table.classify(**v) != Link::Invalid) {
                    table.entries[i] = v;
                    repaired += 1;
                }
            }
        }
        damage.push(Damage::new(
            DamageKind::Corrupt,
            Some(fat1),
            format!("{} FAT entries damaged in copy 1, {repaired} restored from copy 2", suspect.len()),
        ));
        (table, damage)
    }

    fn decode(&self, raw: &[u8], count: usize) -> Vec<u32> {
        (0..count)
            .map(|i| match self.width {
                FatWidth::Fat12 => {
                    let off = i * 3 / 2;
                    let v = u16::from_le_bytes([raw.get(off).copied().unwrap_or(0), raw.get(off + 1).copied().unwrap_or(0)]);
                    u32::from(if i % 2 == 0 { v & 0x0FFF } else { v >> 4 })
                }
                FatWidth::Fat16 => u32::from(strata_kernel::bytes::u16_le(raw, i * 2).unwrap_or(0)),
                FatWidth::Fat32 => strata_kernel::bytes::u32_le(raw, i * 4).unwrap_or(0) & 0x0FFF_FFFF,
                FatWidth::ExFat => strata_kernel::bytes::u32_le(raw, i * 4).unwrap_or(0),
            })
            .collect()
    }

    fn classify(&self, v: u32) -> Link {
        let (bad, eoc) = self.width.marks();
        match v {
            0 => Link::Free,
            v if v >= eoc => Link::End,
            v if v == bad => Link::Bad,
            v if (2..=self.max_cluster).contains(&v) => Link::Next(v),
            _ => Link::Invalid,
        }
    }

    pub(crate) fn link(&self, cluster: u32) -> Link {
        self.entries.get(cluster as usize).map_or(Link::Invalid, |v| self.classify(*v))
    }

    pub(crate) fn is_free(&self, cluster: u32) -> bool {
        self.link(cluster) == Link::Free
    }

    /// Follow a chain from `start`, at most `limit` clusters, stopping at loops.
    pub(crate) fn chain(&self, start: u32, limit: usize) -> Chain {
        let mut clusters = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = start;
        loop {
            if !(2..=self.max_cluster).contains(&cur) {
                return Chain { clusters, end: ChainEnd::Broken("cluster out of range") };
            }
            if !seen.insert(cur) {
                return Chain { clusters, end: ChainEnd::Broken("cluster chain loops") };
            }
            if clusters.len() >= limit {
                return Chain { clusters, end: ChainEnd::Limit };
            }
            clusters.push(cur);
            cur = match self.link(cur) {
                Link::Next(n) => n,
                Link::End => return Chain { clusters, end: ChainEnd::Eoc },
                Link::Free => return Chain { clusters, end: ChainEnd::Broken("chain runs into a free cluster") },
                Link::Bad => return Chain { clusters, end: ChainEnd::Broken("chain runs into a bad cluster") },
                Link::Invalid => return Chain { clusters, end: ChainEnd::Broken("chain hits a damaged FAT entry") },
            };
        }
    }

    /// Allocation map indexed by `cluster - 2`.
    pub(crate) fn used_map(&self) -> ClusterMap {
        let mut map = ClusterMap::new(u64::from(self.max_cluster.saturating_sub(1)));
        for c in 2..=self.max_cluster {
            if !self.is_free(c) {
                map.set_used(u64::from(c - 2));
            }
        }
        map
    }
}
