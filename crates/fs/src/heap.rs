//! Cluster heap geometry and content placement shared by the FAT family (FAT12/16/32, exFAT).

use crate::Extent;
use crate::alloc::{ClusterMap, ExtentList};
use crate::dirbuf::DirBuffer;
use strata_kernel::{ByteRange, Damage, DamageKind};
use strata_source::BlockSource;

/// The data area: clusters numbered from 2, each `cluster_size` bytes, starting at `start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClusterHeap {
    start: u64,
    cluster_size: u64,
    count: u32,
}

impl ClusterHeap {
    pub(crate) fn new(start: u64, cluster_size: u64, count: u32) -> Self {
        Self { start, cluster_size: cluster_size.max(1), count }
    }

    /// Never trust more clusters than the source can hold (bounds FAT reads and maps).
    pub(crate) fn clamped(mut self, source_len: u64) -> Self {
        let fit = source_len.saturating_sub(self.start).div_ceil(self.cluster_size);
        self.count = self.count.min(u32::try_from(fit).unwrap_or(u32::MAX));
        self
    }

    pub(crate) fn start(&self) -> u64 {
        self.start
    }

    pub(crate) fn cluster_size(&self) -> u64 {
        self.cluster_size
    }

    pub(crate) fn count(&self) -> u32 {
        self.count
    }

    /// Highest valid cluster number.
    pub(crate) fn max_cluster(&self) -> u32 {
        self.count.saturating_add(1)
    }

    pub(crate) fn is_cluster(&self, cluster: u32) -> bool {
        (2..=self.max_cluster()).contains(&cluster)
    }

    pub(crate) fn cluster_offset(&self, cluster: u32) -> Option<u64> {
        self.is_cluster(cluster).then(|| self.start + u64::from(cluster - 2) * self.cluster_size)
    }

    pub(crate) fn cluster_range(&self, cluster: u32) -> ByteRange {
        ByteRange::new(self.cluster_offset(cluster).unwrap_or(0), self.cluster_size)
    }

    /// Clusters needed to hold `bytes`, as a cluster count.
    pub(crate) fn clusters_for(&self, bytes: u64) -> u64 {
        bytes.div_ceil(self.cluster_size)
    }

    /// Extents of a cluster list (merging physically consecutive clusters).
    pub(crate) fn extents_of(&self, clusters: &[u32]) -> ExtentList {
        let mut list = ExtentList::default();
        for c in clusters {
            list.push(self.cluster_offset(*c), self.cluster_size);
        }
        list
    }

    /// Read clusters into a directory buffer, merging consecutive ones into single reads.
    pub(crate) fn read_clusters(&self, source: &dyn BlockSource, clusters: &[u32], buf: &mut DirBuffer) {
        let mut i = 0;
        while i < clusters.len() {
            let mut j = i + 1;
            while j < clusters.len() && clusters[j] == clusters[j - 1].wrapping_add(1) {
                j += 1;
            }
            if let Some(off) = self.cluster_offset(clusters[i]) {
                let data = source.read_vec(off, ((j - i) as u64 * self.cluster_size) as usize).unwrap_or_default();
                buf.push(off, &data);
            }
            i = j;
        }
    }

    /// `count` consecutive clusters from `first`, cut at the heap end.
    pub(crate) fn run(&self, first: u32, count: u64) -> Vec<u32> {
        if !self.is_cluster(first) {
            return Vec::new();
        }
        let available = u64::from(self.max_cluster() - first) + 1;
        (0..count.min(available)).map(|i| first + i as u32).collect()
    }

    /// Content assumed to occupy consecutive clusters from `first` (deleted FAT files, exFAT
    /// `NoFatChain` streams). `used` is the current allocation map indexed by `cluster - 2`;
    /// overlap with it is reported only when `deleted` (live contiguous files own their
    /// clusters).
    pub(crate) fn contiguous(&self, first: u32, size: u64, used: &ClusterMap, deleted: bool) -> (Vec<Extent>, Vec<Damage>) {
        let mut damage = Vec::new();
        if size == 0 {
            return (Vec::new(), damage);
        }
        let Some(off) = self.cluster_offset(first) else {
            let note = if deleted { "deleted file's first cluster is unknown" } else { "non-empty file has no valid first cluster" };
            damage.push(Damage::missing(None, note));
            return (Vec::new(), damage);
        };
        let wanted = self.clusters_for(size);
        let clusters = self.run(first, wanted).len() as u64;
        let range = ByteRange::new(off, clusters * self.cluster_size);
        let extents = vec![Extent { file_offset: 0, volume_offset: Some(off), len: size.min(clusters * self.cluster_size) }];
        if clusters < wanted {
            damage.push(Damage::new(DamageKind::Truncated, Some(range), "file runs past the volume end"));
        }
        if deleted && used.any_used(u64::from(first - 2), clusters) {
            damage.push(Damage::missing(Some(range), "clusters now allocated to another file; content likely overwritten"));
        }
        (extents, damage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_and_runs() {
        let heap = ClusterHeap::new(1000, 100, 10);
        assert_eq!(heap.max_cluster(), 11);
        assert_eq!(heap.cluster_offset(2), Some(1000));
        assert_eq!(heap.cluster_offset(12), None);
        assert_eq!(heap.run(10, 5), vec![10, 11]);
        assert_eq!(heap.clamped(1550).count(), 6);
        let (ext, damage) = heap.contiguous(10, 300, &ClusterMap::new(10), true);
        assert_eq!(ext[0].len, 200);
        assert!(damage.iter().any(|d| d.kind() == DamageKind::Truncated));
    }
}
