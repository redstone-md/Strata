//! TAR over identify's header walker: members are slices of the archive bytes.

use crate::entry::{ArchiveEntry, ArchiveFormat};
use crate::reader::{ArchiveReader, MemberData};
use strata_identify::{TarMember, tar_members};
use strata_kernel::{Damage, Error, Result, Timestamp};

pub(crate) struct TarReader<'a> {
    data: &'a [u8],
    members: Vec<TarMember>,
    damage: Vec<Damage>,
}

impl<'a> TarReader<'a> {
    pub fn open(data: &'a [u8]) -> Option<Self> {
        let (members, walk) = tar_members(&data);
        (walk.ok > 0).then_some(Self { data, members, damage: walk.damage })
    }
}

impl ArchiveReader for TarReader<'_> {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Tar
    }

    fn entries(&self) -> Vec<ArchiveEntry> {
        self.members
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let mut e = ArchiveEntry::new(i, &m.name);
                e.size = Some(m.size);
                e.packed = Some(m.size);
                e.is_dir = m.is_dir;
                e.mtime = m.mtime.and_then(Timestamp::from_unix_secs);
                if m.data_offset.saturating_add(m.size) > self.data.len() as u64 {
                    e.damage.push(Damage::truncated(format!("{}: data runs past the end of the archive", m.name)));
                }
                e
            })
            .collect()
    }

    fn damage(&self) -> Vec<Damage> {
        self.damage.clone()
    }

    fn read(&self, entry: &ArchiveEntry, limit: usize) -> Result<MemberData> {
        let m = self.members.get(entry.index).ok_or_else(|| Error::Other(format!("{}: no such member", entry.path)))?;
        let start = usize::try_from(m.data_offset).unwrap_or(usize::MAX).min(self.data.len());
        let want = usize::try_from(m.size).unwrap_or(usize::MAX);
        let end = start.saturating_add(want.min(limit)).min(self.data.len());
        let mut damage = Vec::new();
        if want > limit {
            damage.push(Damage::new(strata_kernel::DamageKind::Missing, None, format!("{}: output capped at {limit} bytes", m.name)));
        }
        Ok((self.data[start..end].to_vec(), damage))
    }
}
