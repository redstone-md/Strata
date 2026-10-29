//! Public builder for a synthetic 1 MiB NTFS volume (feature `testkit`): files in the root
//! with resident content, live or deleted, and a backup boot sector in the last sector.

use super::testimg::{NtfsImage, RecordBuilder, fref};

const DATA: u32 = 0x80;

#[derive(Default)]
pub struct NtfsVolume {
    files: Vec<(String, Vec<u8>, bool)>,
}

impl NtfsVolume {
    pub fn new() -> Self {
        Self::default()
    }

    /// A live file in the root (content stored resident, so keep it under ~600 bytes).
    pub fn file(mut self, name: &str, data: &[u8]) -> Self {
        self.files.push((name.to_string(), data.to_vec(), false));
        self
    }

    /// A deleted file in the root (its MFT record marked free, content still inside).
    pub fn deleted_file(mut self, name: &str, data: &[u8]) -> Self {
        self.files.push((name.to_string(), data.to_vec(), true));
        self
    }

    pub fn finish(self) -> Vec<u8> {
        let mut img = NtfsImage::new();
        for (i, (name, data, deleted)) in self.files.iter().enumerate() {
            let n = 16 + i as u64;
            let mut rec = RecordBuilder::new(n, 1);
            if *deleted {
                rec = rec.deleted();
            }
            img.put(n, rec.std_info().file_name(fref(5, 5), name, 1).resident(DATA, "", data).build());
        }
        let mut bytes = img.finish();
        let boot: Vec<u8> = bytes[..512].to_vec();
        let last = bytes.len() - 512;
        bytes[last..].copy_from_slice(&boot);
        bytes
    }
}
