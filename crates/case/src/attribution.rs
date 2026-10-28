//! Maps an absolute evidence offset to volume and file — the step the manual workflow
//! never had ("90 hits not matched to a file").

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use strata_fs::{EntryState, FileSystem, OwnershipIndex, open_filesystem};
use strata_source::BlockSource;
use strata_volume::Volume;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    pub path: String,
    pub state: EntryState,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribution {
    pub volume: Option<u32>,
    pub file: Option<FileRef>,
}

struct MountedVolume {
    volume: Volume,
    fs: Option<Box<dyn FileSystem>>,
    owners: Option<OwnershipIndex>,
}

/// Volumes and parsed filesystems of one evidence item.
pub struct EvidenceLayout {
    mounted: Vec<MountedVolume>,
}

impl EvidenceLayout {
    /// Parse every volume's filesystem. Volumes whose filesystem cannot be parsed still
    /// attribute offsets to the volume itself.
    pub fn build(disk: &Arc<dyn BlockSource>, volumes: &[Volume]) -> Self {
        let mounted = volumes
            .iter()
            .map(|v| {
                let fs = open_filesystem(v.open(disk.clone()), v.fs).ok();
                let owners = fs.as_ref().map(|f| OwnershipIndex::build(f.entries()));
                MountedVolume { volume: v.clone(), fs, owners }
            })
            .collect();
        Self { mounted }
    }

    pub fn filesystems(&self) -> impl Iterator<Item = (&Volume, &dyn FileSystem)> {
        self.mounted.iter().filter_map(|m| Some((&m.volume, m.fs.as_deref()?)))
    }

    pub fn attribute(&self, offset: u64) -> Attribution {
        let Some(m) = self.mounted.iter().find(|m| m.volume.range.contains(offset)) else {
            return Attribution::default();
        };
        let rel = offset - m.volume.range.start();
        let file = match (&m.fs, &m.owners) {
            (Some(fs), Some(owners)) => owners.owners(rel, fs.entries()).first().and_then(|(id, file_offset)| {
                let e = fs.entry(*id)?;
                Some(FileRef { path: e.path.clone(), state: e.state, file_offset: *file_offset })
            }),
            _ => None,
        };
        Attribution { volume: Some(m.volume.index), file }
    }
}
