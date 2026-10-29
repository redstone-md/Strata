//! Synthetic evidence for workbench tests: an MBR disk with FAT16 partitions holding a few
//! plain files, plus bytes placed in unpartitioned space. All content is made up.

/// Sectors per FAT16 volume (4 MiB, one 512-byte sector per cluster).
const VOLUME_SECTORS: usize = 8192;
const RESERVED: usize = 1;
const FAT_SECTORS: usize = 32;
const ROOT_ENTRIES: usize = 64;

/// A FAT16 volume whose files lie in consecutive clusters of the root directory.
pub struct Fat16 {
    bytes: Vec<u8>,
    next_cluster: u32,
    next_slot: usize,
}

impl Fat16 {
    pub fn new(hidden_sectors: u32) -> Self {
        let mut bytes = vec![0u8; VOLUME_SECTORS * 512];
        let s = &mut bytes[..512];
        s[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        s[3..11].copy_from_slice(b"MSDOS5.0");
        s[11..13].copy_from_slice(&512u16.to_le_bytes());
        s[13] = 1;
        s[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
        s[16] = 2;
        s[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
        s[19..21].copy_from_slice(&(VOLUME_SECTORS as u16).to_le_bytes());
        s[21] = 0xF8;
        s[22..24].copy_from_slice(&(FAT_SECTORS as u16).to_le_bytes());
        s[28..32].copy_from_slice(&hidden_sectors.to_le_bytes());
        s[510] = 0x55;
        s[511] = 0xAA;
        let mut v = Self { bytes, next_cluster: 2, next_slot: 0 };
        v.set_fat(0, 0xFFF8);
        v.set_fat(1, 0xFFFF);
        v
    }

    fn set_fat(&mut self, cluster: u32, value: u16) {
        for copy in 0..2 {
            let off = (RESERVED + copy * FAT_SECTORS) * 512 + cluster as usize * 2;
            self.bytes[off..off + 2].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// Add a file named `name` (8.3, e.g. `NOTES   TXT`) with `data`.
    pub fn file(mut self, name: &[u8; 11], data: &[u8]) -> Self {
        let clusters = data.len().div_ceil(512).max(1) as u32;
        let first = self.next_cluster;
        for c in first..first + clusters {
            self.set_fat(c, if c + 1 == first + clusters { 0xFFFF } else { (c + 1) as u16 });
        }
        let data_start = (RESERVED + 2 * FAT_SECTORS) * 512 + ROOT_ENTRIES * 32;
        let off = data_start + (first as usize - 2) * 512;
        self.bytes[off..off + data.len()].copy_from_slice(data);
        let mut e = [0u8; 32];
        e[..11].copy_from_slice(name);
        e[11] = 0x20;
        let date: u16 = ((2014 - 1980) << 9) | (3 << 5) | 9;
        let time: u16 = (14 << 11) | (5 << 5);
        for at in [14, 22] {
            e[at..at + 2].copy_from_slice(&time.to_le_bytes());
        }
        for at in [16, 18, 24] {
            e[at..at + 2].copy_from_slice(&date.to_le_bytes());
        }
        e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        e[28..32].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let root = (RESERVED + 2 * FAT_SECTORS) * 512 + self.next_slot * 32;
        self.bytes[root..root + 32].copy_from_slice(&e);
        self.next_slot += 1;
        self.next_cluster += clusters;
        self
    }

    pub fn bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// A disk of `len` bytes with FAT16 partitions at the given MiB offsets (MBR type 0x06) and
/// raw `extra` blobs written at absolute offsets.
pub fn disk(len: usize, partitions: Vec<(usize, Fat16)>, extra: &[(usize, &[u8])]) -> Vec<u8> {
    let mut disk = vec![0u8; len];
    for (i, (mib, vol)) in partitions.into_iter().enumerate() {
        let start = mib << 20;
        let entry = 446 + i * 16;
        disk[entry + 4] = 0x06;
        disk[entry + 8..entry + 12].copy_from_slice(&((start / 512) as u32).to_le_bytes());
        disk[entry + 12..entry + 16].copy_from_slice(&(VOLUME_SECTORS as u32).to_le_bytes());
        let bytes = vol.bytes();
        disk[start..start + bytes.len()].copy_from_slice(&bytes);
    }
    disk[510] = 0x55;
    disk[511] = 0xAA;
    for (at, blob) in extra {
        disk[*at..*at + blob.len()].copy_from_slice(blob);
    }
    disk
}
