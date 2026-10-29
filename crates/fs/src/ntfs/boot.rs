//! NTFS boot sector (`$Boot`): geometry and where `$MFT` lives.

use strata_kernel::bytes::{u16_le, u64_le, u8_at};
use strata_kernel::{ByteRange, Damage};
use strata_source::BlockSource;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NtfsBoot {
    cluster_size: u64,
    total_clusters: u64,
    mft_lcn: u64,
    mirror_lcn: u64,
    record_size: usize,
}

impl NtfsBoot {
    pub(super) fn parse(s: &[u8]) -> Option<Self> {
        if s.get(3..11)? != b"NTFS    " {
            return None;
        }
        let bps = u64::from(u16_le(s, 0x0B)?);
        if !(256..=4096).contains(&bps) || !bps.is_power_of_two() {
            return None;
        }
        let spc_raw = u8_at(s, 0x0D)?;
        // Values above 0x80 encode 2^(256 - value) sectors (clusters of 64 KiB and up).
        let spc = match spc_raw {
            0 => return None,
            1..=0x80 => u64::from(spc_raw),
            _ => 1u64 << (256 - u32::from(spc_raw)).min(24),
        };
        let cluster_size = bps.checked_mul(spc).filter(|c| c.is_power_of_two() && *c <= 2 << 20)?;
        let total_clusters = u64_le(s, 0x28)? / spc;
        let mft_lcn = u64_le(s, 0x30)?;
        let mirror_lcn = u64_le(s, 0x38)?;
        let cpr = u8_at(s, 0x40)? as i8;
        let record_size = if cpr > 0 {
            u64::from(cpr.unsigned_abs()).checked_mul(cluster_size)?
        } else {
            1u64 << u32::from(cpr.unsigned_abs()).min(31)
        };
        if !(256..=65536).contains(&record_size) || !record_size.is_power_of_two() || mft_lcn >= total_clusters {
            return None;
        }
        Some(Self { cluster_size, total_clusters, mft_lcn, mirror_lcn, record_size: record_size as usize })
    }

    /// Primary boot sector, else the backup NTFS keeps in the volume's last sector.
    pub(super) fn locate(source: &dyn BlockSource) -> (Option<Self>, Vec<Damage>) {
        let at = |off: u64| source.read_vec(off, 512).ok().and_then(|s| Self::parse(&s)).map(|b| b.clamped(source.len()));
        if let Some(boot) = at(0) {
            return (Some(boot), Vec::new());
        }
        let backup_off = source.len().saturating_sub(512) & !511;
        let note = Damage::corrupt(ByteRange::new(0, 512), "primary NTFS boot sector invalid");
        match at(backup_off) {
            Some(boot) => (Some(boot), vec![note, Damage::corrupt(ByteRange::new(backup_off, 512), "using backup boot sector")]),
            None => (None, vec![note]),
        }
    }

    /// A damaged sector can declare an absurd size; never trust more clusters than the
    /// source holds (bounds every per-cluster allocation).
    fn clamped(mut self, source_len: u64) -> Self {
        self.total_clusters = self.total_clusters.min(source_len.div_ceil(self.cluster_size));
        self
    }

    pub(super) fn cluster_size(&self) -> u64 {
        self.cluster_size
    }

    pub(super) fn total_clusters(&self) -> u64 {
        self.total_clusters
    }

    pub(super) fn mft_offset(&self) -> u64 {
        self.mft_lcn.saturating_mul(self.cluster_size)
    }

    pub(super) fn mirror_offset(&self) -> u64 {
        self.mirror_lcn.saturating_mul(self.cluster_size)
    }

    pub(super) fn record_size(&self) -> usize {
        self.record_size
    }

    /// Byte offset of cluster `lcn`, if it lies inside the volume.
    pub(super) fn cluster_offset(&self, lcn: u64, len: u64) -> Option<u64> {
        (lcn.checked_add(len)? <= self.total_clusters).then(|| lcn * self.cluster_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_geometry() {
        let mut s = vec![0u8; 512];
        s[3..11].copy_from_slice(b"NTFS    ");
        assert!(NtfsBoot::parse(&s).is_none());
        s[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        s[0x0D] = 8;
        s[0x28..0x30].copy_from_slice(&8000u64.to_le_bytes());
        s[0x30..0x38].copy_from_slice(&4u64.to_le_bytes());
        s[0x40] = 0xF6;
        let boot = NtfsBoot::parse(&s).unwrap();
        assert_eq!((boot.cluster_size(), boot.record_size(), boot.total_clusters()), (4096, 1024, 1000));
        s[0x40] = 0x7F;
        assert!(NtfsBoot::parse(&s).is_none());
        assert!(NtfsBoot::parse(&s[..20]).is_none());
    }
}
