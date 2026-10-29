/// Knobs for [`crate::open_filesystem_with`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FsOptions {
    carve_records: bool,
}

impl FsOptions {
    /// Also sweep unallocated space for stray metadata records (NTFS `FILE` records left by an
    /// old or relocated `$MFT`). Reads all free space, so it is off by default.
    pub fn with_record_carving(mut self, on: bool) -> Self {
        self.carve_records = on;
        self
    }

    pub fn carve_records(&self) -> bool {
        self.carve_records
    }
}
