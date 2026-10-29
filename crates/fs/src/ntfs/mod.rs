//! NTFS: `$MFT` walk with deleted records, orphans, alternate streams and compressed files.

mod assemble;
mod attr;
mod boot;
mod carve;
mod freespace;
mod lznt1;
mod meta;
mod mft;
mod record;
mod runs;
mod stream;
mod tree;

#[cfg(feature = "testkit")]
pub(crate) mod kit;
#[cfg(any(test, feature = "testkit"))]
#[allow(dead_code)]
mod testimg;
#[cfg(test)]
mod tests;

use crate::tree::FsTree;
use crate::{EntryState, FileEntry, FileId, FileSystem, FsOptions};
use assemble::{Assembler, Built};
use boot::NtfsBoot;
use mft::Mft;
use record::MftRecord;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use strata_kernel::{ByteRange, Damage, Error, Result};
use strata_source::BlockSource;
use strata_volume::FsKind;
use tree::TreeBuilder;

pub(crate) struct NtfsFileSystem {
    tree: FsTree,
    /// Entry index -> compression unit size in bytes, for LZNT1-compressed files.
    compressed: HashMap<usize, u64>,
}

impl NtfsFileSystem {
    pub(crate) fn open(source: Arc<dyn BlockSource>, options: FsOptions) -> Result<Self> {
        let src = source.as_ref();
        let (boot, mut damage) = NtfsBoot::locate(src);
        let boot = boot.ok_or_else(|| Error::format("no valid NTFS boot sector"))?;
        let (mft, mft_damage) = Mft::locate(src, &boot);
        damage.extend(mft_damage);
        let mft = mft.ok_or_else(|| Error::format("$MFT not found"))?;

        let mut records: Vec<Option<MftRecord>> = Vec::new();
        damage.extend(mft.read_records(src, |r| {
            let n = r.number() as usize;
            if records.len() <= n {
                records.resize_with(n + 1, || None);
            }
            records[n] = Some(r);
        }));
        let mut builder = TreeBuilder::default();
        let live: Vec<(&MftRecord, u64)> =
            records.iter().flatten().map(|r| (r, mft.record_volume_offset(r.number()).unwrap_or(0))).collect();
        Self::add_records(&mut builder, &live, &boot, |_, _| {});
        drop(live);
        drop(records);

        let (mut entries, mut compressed) = builder.finish();
        let (unallocated, free_damage) = freespace::unallocated(src, &boot, &entries, mft.extents());
        damage.extend(free_damage);
        let mut stray = carve::after_mft(src, &boot, mft.extents(), &unallocated);
        if options.carve_records() {
            let seen: HashSet<u64> = stray.iter().map(|(_, at)| *at).collect();
            stray.extend(carve::carve(src, &boot, &unallocated).into_iter().filter(|(_, at)| !seen.contains(at)));
        }
        Self::add_previous(&mut entries, &mut compressed, &boot, stray);
        let tree = FsTree::new(FsKind::Ntfs, source, entries, unallocated, damage);
        Ok(Self { tree, compressed })
    }

    /// Build files from base records and their extension records; `mark` sees each built file
    /// with the volume offset of its record.
    fn add_records(builder: &mut TreeBuilder, records: &[(&MftRecord, u64)], boot: &NtfsBoot, mut mark: impl FnMut(&mut Built, u64)) {
        let assembler = Assembler::new(boot);
        let mut extensions: HashMap<u64, Vec<&MftRecord>> = HashMap::new();
        for (rec, _) in records {
            if let Some(base) = rec.base() {
                extensions.entry(base.record()).or_default().push(rec);
            }
        }
        for &(rec, offset) in records.iter().filter(|(r, _)| r.base().is_none()) {
            let ext: Vec<&MftRecord> = extensions
                .get(&rec.number())
                .into_iter()
                .flatten()
                .copied()
                .filter(|e| e.base().is_some_and(|b| b.points_to(rec.seq(), rec.in_use())))
                .collect();
            if let Some(mut built) = assembler.build(rec, &ext, offset) {
                mark(&mut built, offset);
                builder.add(built);
            }
        }
    }

    /// Records outside the live `$MFT` (an older `$MFT` left by a quick format, stray records in
    /// free space) are rebuilt into their own tree with folders and names, under
    /// [`tree::REFORMATTED`]. None of it belongs to the current file system, so files read as
    /// deleted; those whose folder is gone too land in its `$Orphans`.
    fn add_previous(entries: &mut Vec<FileEntry>, compressed: &mut HashMap<usize, u64>, boot: &NtfsBoot, stray: Vec<(MftRecord, u64)>) {
        if stray.is_empty() {
            return;
        }
        let Some(root) = entries.iter().position(|e| e.parent.is_none()) else { return };
        // One record per number: several copies of an old `$MFT` overlap; the one in use wins.
        let mut by_number: HashMap<u64, (MftRecord, u64)> = HashMap::new();
        for (rec, at) in stray {
            match by_number.entry(rec.number()) {
                Entry::Occupied(mut o) if rec.in_use() && !o.get().0.in_use() => {
                    o.insert((rec, at));
                }
                Entry::Occupied(_) => {}
                Entry::Vacant(v) => {
                    v.insert((rec, at));
                }
            }
        }
        let records: Vec<(&MftRecord, u64)> = by_number.values().map(|(r, at)| (r, *at)).collect();
        let mut builder = TreeBuilder::default();
        let rs = boot.record_size() as u64;
        Self::add_records(&mut builder, &records, boot, |built, at| {
            built.entry_mut().damage.push(Damage::corrupt(ByteRange::new(at, rs), "MFT record from before the volume was reformatted"));
        });
        let (old, old_compressed) = builder.finish();
        let base = entries.len();
        for (i, mut entry) in old.into_iter().enumerate() {
            match entry.parent {
                None => {
                    entry.name = tree::REFORMATTED.to_string();
                    entry.path = tree::REFORMATTED.to_string();
                    entry.parent = Some(FileId::new(root));
                    entry.state = EntryState::Orphan;
                }
                Some(p) => {
                    entry.parent = Some(FileId::new(base + p.index()));
                    entry.state = if entry.path.starts_with(tree::ORPHANS) { EntryState::Orphan } else { EntryState::Deleted };
                    entry.path = crate::entry::join_path(tree::REFORMATTED, &entry.path);
                }
            }
            if let Some(unit) = old_compressed.get(&i) {
                compressed.insert(base + i, *unit);
            }
            entries.push(entry);
        }
    }
}

impl FileSystem for NtfsFileSystem {
    fn kind(&self) -> FsKind {
        self.tree.kind()
    }

    fn source(&self) -> &Arc<dyn BlockSource> {
        self.tree.source()
    }

    fn entries(&self) -> &[FileEntry] {
        self.tree.entries()
    }

    fn children(&self, dir: FileId) -> Vec<FileId> {
        self.tree.children(dir)
    }

    fn unallocated(&self) -> Vec<ByteRange> {
        self.tree.unallocated()
    }

    fn damage(&self) -> &[Damage] {
        self.tree.damage()
    }

    fn read(&self, id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let entry = self.entry(id).ok_or(Error::Other(format!("no file {id:?}")))?;
        match self.compressed.get(&id.index()) {
            Some(&unit) => lznt1::CompressedReader::new(self.source().as_ref(), entry, unit).read(offset, buf),
            None => crate::ExtentReader::new(self.source().as_ref(), entry).read(offset, buf),
        }
    }
}
