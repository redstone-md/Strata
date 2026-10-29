//! Public builder for synthetic FAT16 volumes, so other crates can test recovery end to end
//! (feature `testkit`). Files are laid out contiguously in the root directory.

use super::testimg::{CS, Dir, FatImage, deleted, short, with_lfn};

/// A 4 MiB FAT16 volume (512-byte clusters) under construction.
pub struct FatVolume {
    img: FatImage,
    next_cluster: u32,
    files: u32,
}

impl Default for FatVolume {
    fn default() -> Self {
        Self { img: FatImage::fat16(), next_cluster: 10, files: 0 }
    }
}

impl FatVolume {
    pub fn new() -> Self {
        Self::default()
    }

    fn place(&mut self, name: &str, data: &[u8]) -> (Vec<[u8; 32]>, Vec<u32>) {
        self.files += 1;
        let count = data.len().div_ceil(CS).max(1) as u32;
        let clusters: Vec<u32> = (self.next_cluster..self.next_cluster + count).collect();
        self.next_cluster += count;
        self.img.write_clusters(&clusters, data);
        let short_name: [u8; 11] = *format!("FILE{:04}BIN", self.files).as_bytes().first_chunk().unwrap_or(&[b'_'; 11]);
        let entry = short(&short_name, 0x20, clusters[0], data.len() as u32);
        (with_lfn(name, entry), clusters)
    }

    /// A live file in the root directory.
    pub fn file(mut self, name: &str, data: &[u8]) -> Self {
        let (slots, clusters) = self.place(name, data);
        self.img.chain(&clusters);
        self.img.add(Dir::Root, &slots);
        self
    }

    /// A deleted file: directory slots marked free, FAT chain cleared, content left in place.
    pub fn deleted_file(mut self, name: &str, data: &[u8]) -> Self {
        let (slots, _) = self.place(name, data);
        self.img.add(Dir::Root, &deleted(slots));
        self
    }

    /// A deleted file whose clusters were since reused by the live file written next
    /// (`reuse` bytes of new content over the start of the old one).
    pub fn overwritten_file(mut self, name: &str, data: &[u8], reuse: &str, new_data: &[u8]) -> Self {
        let first = self.next_cluster;
        let (slots, _) = self.place(name, data);
        self.img.add(Dir::Root, &deleted(slots));
        let saved = self.next_cluster;
        self.next_cluster = first;
        let file = self.file(reuse, new_data);
        Self { next_cluster: saved.max(file.next_cluster), ..file }
    }

    pub fn finish(self) -> Vec<u8> {
        self.img.finish()
    }
}
