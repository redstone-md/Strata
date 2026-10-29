//! exFAT boot region: main boot sector geometry and the main/backup boot region checksums.

use crate::fat::table::{FatLayout, FatWidth};
use crate::heap::ClusterHeap;
use strata_kernel::bytes::{u8_at, u16_le, u32_le, u64_le};
use strata_kernel::{ByteRange, Damage};
use strata_source::BlockSource;

/// Sectors in one boot region (boot sector, 8 extended, OEM, reserved, checksum).
const REGION_SECTORS: u64 = 12;
/// Sectors the checksum covers (everything but the checksum sector).
const SUMMED_SECTORS: usize = 11;
const OEM: &[u8; 8] = b"EXFAT   ";
const ACTIVE_FAT_FLAG: u16 = 0x0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExfatBoot {
    sector_size: u64,
    fat_offset: u64,
    fat_bytes: u64,
    fat_count: u8,
    second_fat_active: bool,
    root_cluster: u32,
    heap: ClusterHeap,
}

impl ExfatBoot {
    pub(super) fn parse(s: &[u8]) -> Option<Self> {
        if s.get(510..512)? != [0x55, 0xAA] || s.get(3..11)? != OEM {
            return None;
        }
        let bps_shift = u8_at(s, 108)?;
        let spc_shift = u8_at(s, 109)?;
        // Sectors 512..4096 bytes, clusters up to 32 MiB (spec limits).
        if !(9..=12).contains(&bps_shift) || u32::from(bps_shift) + u32::from(spc_shift) > 25 {
            return None;
        }
        let sector = 1u64 << bps_shift;
        let fat_offset = u64::from(u32_le(s, 80)?);
        let fat_length = u64::from(u32_le(s, 84)?);
        let heap_offset = u64::from(u32_le(s, 88)?);
        let cluster_count = u32_le(s, 92)?;
        let root_cluster = u32_le(s, 96)?;
        let fat_count = u8_at(s, 110)?;
        let sane = fat_offset >= 2 * REGION_SECTORS
            && fat_length > 0
            && (1..=2).contains(&fat_count)
            && heap_offset >= fat_offset + u64::from(fat_count) * fat_length
            && cluster_count > 0
            && root_cluster >= 2;
        if !sane {
            return None;
        }
        let heap = ClusterHeap::new(heap_offset * sector, sector << spc_shift, cluster_count);
        Some(Self {
            sector_size: sector,
            fat_offset: fat_offset * sector,
            fat_bytes: fat_length * sector,
            fat_count,
            second_fat_active: u16_le(s, 106)? & ACTIVE_FAT_FLAG != 0 && fat_count == 2,
            root_cluster,
            heap: heap.clamped(u64_le(s, 72)?.saturating_mul(sector)),
        })
    }

    /// Main boot region, falling back to the backup one; both checksums are verified.
    pub(super) fn locate(source: &dyn BlockSource) -> (Option<Self>, Vec<Damage>) {
        let mut damage = Vec::new();
        let first = source.read_vec(0, 512).ok().and_then(|s| Self::parse(&s));
        let sectors: Vec<u64> = match &first {
            Some(b) => vec![b.sector_size],
            None => vec![512, 1024, 2048, 4096],
        };
        let mut chosen = first.clone();
        for sector in sectors {
            let region = |n: u64| ByteRange::new(n * REGION_SECTORS * sector, REGION_SECTORS * sector);
            let main_ok = Self::region_checksum_ok(source, region(0), sector);
            let backup_ok = Self::region_checksum_ok(source, region(1), sector);
            let backup = source.read_vec(region(1).start(), 512).ok().and_then(|s| Self::parse(&s));
            if chosen.is_none() && backup.as_ref().is_some_and(|b| b.sector_size == sector) {
                damage.push(Damage::corrupt(ByteRange::new(0, 512), "exFAT boot sector invalid; using backup boot region"));
                chosen = backup;
            }
            if chosen.is_some() {
                if !main_ok {
                    damage.push(Damage::corrupt(region(0), "exFAT main boot region checksum mismatch"));
                }
                if !backup_ok {
                    damage.push(Damage::corrupt(region(1), "exFAT backup boot region checksum mismatch"));
                }
                break;
            }
        }
        if chosen.is_none() {
            damage.push(Damage::corrupt(ByteRange::new(0, 512), "no valid exFAT boot sector"));
        }
        (chosen.map(|b| Self { heap: b.heap.clamped(source.len()), ..b }), damage)
    }

    fn region_checksum_ok(source: &dyn BlockSource, region: ByteRange, sector: u64) -> bool {
        let Ok(bytes) = source.read_vec(region.start(), region.len() as usize) else {
            return false;
        };
        let summed = bytes.get(..SUMMED_SECTORS * sector as usize);
        let stored = bytes.get(SUMMED_SECTORS * sector as usize..);
        match (summed, stored) {
            (Some(summed), Some(stored)) if !stored.is_empty() => {
                let sum = boot_checksum(summed);
                stored.as_chunks::<4>().0.iter().all(|c| u32::from_le_bytes(*c) == sum)
            }
            _ => false,
        }
    }

    pub(super) fn heap(&self) -> &ClusterHeap {
        &self.heap
    }

    pub(super) fn root_cluster(&self) -> u32 {
        self.root_cluster
    }

    /// The active FAT first, the other copy (TexFAT) as backup.
    pub(super) fn fat_layout(&self) -> FatLayout {
        let mut copies: Vec<u64> = (0..u64::from(self.fat_count)).map(|i| self.fat_offset + i * self.fat_bytes).collect();
        if self.second_fat_active {
            copies.reverse();
        }
        FatLayout::new(FatWidth::ExFat, copies, self.fat_bytes, self.heap.max_cluster())
    }
}

/// Boot region checksum: rotate-right-and-add over the first 11 sectors, skipping the volume
/// flags (106, 107) and percent-in-use (112) bytes that change at run time.
pub(super) fn boot_checksum(summed: &[u8]) -> u32 {
    summed
        .iter()
        .enumerate()
        .filter(|(i, _)| !matches!(i, 106 | 107 | 112))
        .fold(0u32, |sum, (_, b)| sum.rotate_right(1).wrapping_add(u32::from(*b)))
}
