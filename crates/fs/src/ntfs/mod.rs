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

#[cfg(test)]
mod testimg;
#[cfg(test)]
mod tests;

use crate::tree::FsTree;
use crate::{EntryState, FileEntry, FileId, FileSystem, FsOptions};
use assemble::Assembler;
use boot::NtfsBoot;
use mft::Mft;
use record::MftRecord;
use std::collections::HashMap;
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
        Self::add_live(&mut builder, &records, &boot, &mft);
        drop(records);

        let (mut entries, mut compressed) = builder.finish();
        let (unallocated, free_damage) = freespace::unallocated(src, &boot, &entries, mft.extents());
        damage.extend(free_damage);
        if options.carve_records() {
            Self::add_carved(&mut entries, &mut compressed, src, &boot, &unallocated);
        }
        let tree = FsTree::new(FsKind::Ntfs, source, entries, unallocated, damage);
        Ok(Self { tree, compressed })
    }

    fn add_live(builder: &mut TreeBuilder, records: &[Option<MftRecord>], boot: &NtfsBoot, mft: &Mft) {
        let assembler = Assembler::new(boot);
        let mut extensions: HashMap<u64, Vec<&MftRecord>> = HashMap::new();
        for rec in records.iter().flatten() {
            if let Some(base) = rec.base() {
                extensions.entry(base.record()).or_default().push(rec);
            }
        }
        for rec in records.iter().flatten().filter(|r| r.base().is_none()) {
            let ext: Vec<&MftRecord> = extensions
                .get(&rec.number())
                .into_iter()
                .flatten()
                .copied()
                .filter(|e| e.base().is_some_and(|b| b.points_to(rec.seq(), rec.in_use())))
                .collect();
            let offset = mft.record_volume_offset(rec.number()).unwrap_or(0);
            if let Some(built) = assembler.build(rec, &ext, offset) {
                builder.add(built);
            }
        }
    }

    /// Carved records join the finished tree directly under `$Orphans`.
    fn add_carved(
        entries: &mut Vec<FileEntry>,
        compressed: &mut HashMap<usize, u64>,
        src: &dyn BlockSource,
        boot: &NtfsBoot,
        unallocated: &[ByteRange],
    ) {
        let Some(orphans) = entries.iter().position(|e| e.native_id == u64::MAX && e.path == tree::ORPHANS) else { return };
        let assembler = Assembler::new(boot);
        for (rec, at) in carve::carve(src, boot, unallocated) {
            let Some(mut built) = assembler.build(&rec, &[], at) else { continue };
            let unit = built.compression_unit();
            let entry = built.entry_mut();
            entry.state = EntryState::Orphan;
            entry.parent = Some(FileId::new(orphans));
            entry.path = crate::entry::join_path(tree::ORPHANS, &entry.name);
            entry.damage.push(Damage::corrupt(ByteRange::new(at, boot.record_size() as u64), "carved MFT record from free space"));
            if let Some(unit) = unit {
                compressed.insert(entries.len(), unit);
            }
            entries.push(built.into_entry());
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
