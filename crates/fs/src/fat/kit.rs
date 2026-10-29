//! Public builder for synthetic FAT16 volumes, so other crates can test recovery end to end
//! (feature `testkit`). Files are laid out contiguously, in the root or in folders of it.

use super::testimg::{CS, Dir, FatImage, deleted, dots, short, with_lfn};
use std::collections::HashMap;

/// A 4 MiB FAT16 volume (512-byte clusters) under construction.
pub struct FatVolume {
    img: FatImage,
    next_cluster: u32,
    entries: u32,
    folders: HashMap<String, u32>,
}

impl Default for FatVolume {
    fn default() -> Self {
        Self { img: FatImage::fat16(), next_cluster: 10, entries: 0, folders: HashMap::new() }
    }
}

impl FatVolume {
    pub fn new() -> Self {
        Self::default()
    }

    fn short_name(&mut self, prefix: &str) -> [u8; 11] {
        self.entries += 1;
        *format!("{prefix}{:0w$}", self.entries, w = 11 - prefix.len()).as_bytes().first_chunk().unwrap_or(&[b'_'; 11])
    }

    fn place(&mut self, name: &str, data: &[u8]) -> (Vec<[u8; 32]>, Vec<u32>) {
        let count = data.len().div_ceil(CS).max(1) as u32;
        let clusters: Vec<u32> = (self.next_cluster..self.next_cluster + count).collect();
        self.next_cluster += count;
        self.img.write_clusters(&clusters, data);
        let entry = short(&self.short_name("F"), 0x20, clusters[0], data.len() as u32);
        (with_lfn(name, entry), clusters)
    }

    /// The directory a file goes to: the root for `""`, else a folder in the root (one
    /// cluster, created on first use).
    fn folder(&mut self, folder: &str) -> Dir {
        if folder.is_empty() {
            return Dir::Root;
        }
        if let Some(c) = self.folders.get(folder) {
            return Dir::Cluster(*c);
        }
        let c = self.next_cluster;
        self.next_cluster += 1;
        self.img.chain(&[c]);
        let name = self.short_name("D");
        self.img.add(Dir::Root, &with_lfn(folder, short(&name, 0x10, c, 0)));
        self.img.add(Dir::Cluster(c), &dots(c, 0));
        self.folders.insert(folder.to_string(), c);
        Dir::Cluster(c)
    }

    /// A live file in the root directory.
    pub fn file(self, name: &str, data: &[u8]) -> Self {
        self.file_in("", name, data)
    }

    /// A deleted file: directory slots marked free, FAT chain cleared, content left in place.
    pub fn deleted_file(self, name: &str, data: &[u8]) -> Self {
        self.deleted_file_in("", name, data)
    }

    /// A live file in a folder of the root (`""` = the root itself).
    pub fn file_in(mut self, folder: &str, name: &str, data: &[u8]) -> Self {
        let dir = self.folder(folder);
        let (slots, clusters) = self.place(name, data);
        self.img.chain(&clusters);
        self.img.add(dir, &slots);
        self
    }

    /// A deleted file in a folder of the root.
    pub fn deleted_file_in(mut self, folder: &str, name: &str, data: &[u8]) -> Self {
        let dir = self.folder(folder);
        let (slots, _) = self.place(name, data);
        self.img.add(dir, &deleted(slots));
        self
    }

    /// A deleted file whose clusters were since reused by the live file `reuse`.
    pub fn overwritten_file(mut self, name: &str, data: &[u8], reuse: &str, new_data: &[u8]) -> Self {
        let first = self.next_cluster;
        let (slots, _) = self.place(name, data);
        self.img.add(Dir::Root, &deleted(slots));
        let after = self.next_cluster;
        self.next_cluster = first;
        let mut file = self.file(reuse, new_data);
        file.next_cluster = file.next_cluster.max(after);
        file
    }

    pub fn finish(self) -> Vec<u8> {
        self.img.finish()
    }
}
