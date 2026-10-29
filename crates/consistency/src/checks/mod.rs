//! The checks, one module per kind of evidence: the file index ([`file_table`]), when the
//! system was installed and the volume formatted ([`history`]), user activity
//! ([`activity`]), cleaning and wiping programs ([`cleaning`]) and where findings lie
//! ([`free_space`]). Each reads the whole [`DiskInputs`] and adds observations.

mod activity;
mod cleaning;
mod file_table;
mod free_space;
mod history;

use crate::inputs::DiskInputs;
use crate::observation::Observation;

pub(crate) trait Check {
    fn observe(&self, disk: &DiskInputs, out: &mut Vec<Observation>);
}

/// Every check, in the order their observations are listed within a severity.
pub(crate) const ALL: &[&dyn Check] =
    &[&file_table::FileTableCheck, &history::HistoryCheck, &free_space::FreeSpaceCheck, &cleaning::CleaningCheck, &activity::ActivityCheck];

/// Volumes smaller than this are left out of the coverage checks: boot, EFI and reserved
/// partitions hold a few files by design.
pub(crate) const SMALL_VOLUME: u64 = 2 << 30;

/// Findings in free space or deleted entries that show older data lay under what is listed.
pub(crate) const OLDER_DATA_FINDINGS: u64 = 100;
/// Deleted entries that show the same.
pub(crate) const OLDER_DATA_DELETED: u64 = 100;

/// The disk shows data older than what its file system lists.
pub(crate) fn older_data(disk: &DiskInputs) -> bool {
    disk.hits.free + disk.hits.deleted >= OLDER_DATA_FINDINGS || disk.volumes.iter().map(|v| v.deleted.files + v.orphan.files).sum::<u64>() >= OLDER_DATA_DELETED
}
