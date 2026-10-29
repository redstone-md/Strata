//! The file allocation table: cluster links, chains with loop protection, free clusters.

use super::bpb::Bpb;
use crate::alloc::ClusterMap;
use std::collections::HashSet;
use strata_kernel::{ByteRange, Damage, DamageKind};
use strata_source::BlockSource;
use strata_volume::FsKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Link {
    Free,
    Next(u32),
    End,
    Bad,
    /// Reserved or out-of-range value: the entry itself is damaged.
    Invalid,
}

/// Why a chain stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ChainEnd {
    Eoc,
    Limit,
    Broken(&'static str),
}

pub(super) struct Chain {
    clusters: Vec<u32>,
    end: ChainEnd,
}

impl Chain {
    pub(super) fn clusters(&self) -> &[u32] {
        &self.clusters
    }

    pub(super) fn end(&self) -> ChainEnd {
        self.end
    }
}

pub(super) struct FatTable {
    entries: Vec<u32>,
    width: u8,
    max_cluster: u32,
}

impl FatTable {
    /// Load FAT copy 1; entries that look damaged (invalid values, unreadable sectors) are
    /// taken from copy 2 when that one has a sane value.
    pub(super) fn load(source: &dyn BlockSource, bpb: &Bpb) -> (Self, Vec<Damage>) {
        let width = match bpb.kind() {
            FsKind::Fat12 => 12,
            FsKind::Fat16 => 16,
            _ => 32,
        };
        let count = bpb.max_cluster() as usize + 1;
        let bytes = ((count as u64 * u64::from(width)).div_ceil(8)).min(bpb.fat_bytes());
        let read = |copy: u32| -> Option<Vec<u8>> { source.read_vec(bpb.fat_offset(copy)?, bytes as usize).ok() };
        let mut table = Self { entries: Vec::new(), width, max_cluster: bpb.max_cluster() };
        let mut damage = Vec::new();
        let Some(primary) = read(0) else {
            damage.push(Damage::new(DamageKind::Unreadable, None, "FAT copy 1 unreadable"));
            return (table, damage);
        };
        table.entries = table.decode(&primary, count);
        let fat1 = ByteRange::new(bpb.fat_offset(0).unwrap_or(0), bytes);
        let unreadable: Vec<ByteRange> = source.damage().iter().filter_map(|d| d.intersect(&fat1)).collect();
        let suspect: Vec<usize> = (2..count)
            .filter(|&i| {
                let at = fat1.start() + (i as u64 * u64::from(width)) / 8;
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
                12 => {
                    let off = i * 3 / 2;
                    let v = u16::from_le_bytes([raw.get(off).copied().unwrap_or(0), raw.get(off + 1).copied().unwrap_or(0)]);
                    u32::from(if i % 2 == 0 { v & 0x0FFF } else { v >> 4 })
                }
                16 => u32::from(strata_kernel::bytes::u16_le(raw, i * 2).unwrap_or(0)),
                _ => strata_kernel::bytes::u32_le(raw, i * 4).unwrap_or(0) & 0x0FFF_FFFF,
            })
            .collect()
    }

    fn classify(&self, v: u32) -> Link {
        let (bad, eoc) = match self.width {
            12 => (0xFF7, 0xFF8),
            16 => (0xFFF7, 0xFFF8),
            _ => (0x0FFF_FFF7, 0x0FFF_FFF8),
        };
        match v {
            0 => Link::Free,
            v if v >= eoc => Link::End,
            v if v == bad => Link::Bad,
            v if (2..=self.max_cluster).contains(&v) => Link::Next(v),
            _ => Link::Invalid,
        }
    }

    pub(super) fn link(&self, cluster: u32) -> Link {
        self.entries.get(cluster as usize).map_or(Link::Invalid, |v| self.classify(*v))
    }

    pub(super) fn is_free(&self, cluster: u32) -> bool {
        self.link(cluster) == Link::Free
    }

    /// Follow a chain from `start`, at most `limit` clusters, stopping at loops.
    pub(super) fn chain(&self, start: u32, limit: usize) -> Chain {
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
    pub(super) fn used_map(&self) -> ClusterMap {
        let mut map = ClusterMap::new(u64::from(self.max_cluster.saturating_sub(1)));
        for c in 2..=self.max_cluster {
            if !self.is_free(c) {
                map.set_used(u64::from(c - 2));
            }
        }
        map
    }
}
