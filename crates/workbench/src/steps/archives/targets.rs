//! Which archives the unpack step opens: files whose content is an archive (live, deleted,
//! orphaned, renamed) and archives carved from free space.

use std::collections::HashMap;
use std::sync::Arc;
use strata_archive::ArchiveFormat;
use strata_carve::{CarvedFile, Carver};
use strata_case::{Case, HitQuery};
use strata_fs::{EntryState, ExtentReader, FileEntry};
use strata_identify::{Category, Identifier, Registry, TypeId};
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Result};
use strata_source::BlockSource;

/// Archives larger than this are not read into memory (counted as skipped).
pub(crate) const MAX_ARCHIVE_BYTES: u64 = 1 << 30;
/// Head bytes identified when the classify step has not run.
const HEAD_BYTES: usize = 64 * 1024;

/// Where an archive came from; its bytes are read only when it is processed.
pub(crate) enum Origin {
    File { volume: u32, file_idx: usize },
    Carved(Box<CarvedFile>),
}

pub(crate) struct Target {
    /// Path on the evidence, or `$Carved/<type>@<offset>`.
    pub name: String,
    pub volume: Option<u32>,
    pub state: EntryState,
    /// Absolute evidence offset of the archive's first byte (0 for resident files).
    pub offset: u64,
    pub size: u64,
    pub hint: Option<TypeId>,
    pub origin: Origin,
}

/// Content types the unpacker has a reader for, by display name (as stored in `files`).
fn archive_types() -> Vec<&'static str> {
    Registry::all()
        .iter()
        .filter(|t| t.category == Category::Archive && ArchiveFormat::for_type(t.id).is_some())
        .map(|t| t.name)
        .collect()
}

fn type_by_name(name: &str) -> Option<TypeId> {
    Registry::all().iter().find(|t| t.name == name).map(|t| t.id)
}

pub(crate) struct TargetFinder<'a> {
    case: &'a Case,
    /// The evidence, read through the job's byte counter.
    source: Arc<dyn BlockSource>,
}

impl<'a> TargetFinder<'a> {
    pub fn new(case: &'a Case, source: Arc<dyn BlockSource>) -> Self {
        Self { case, source }
    }

    pub fn find(&self, id: EvidenceId) -> Result<Vec<Target>> {
        let mut out = self.files(id)?;
        out.extend(self.carved(id)?);
        Ok(out)
    }

    fn files(&self, id: EvidenceId) -> Result<Vec<Target>> {
        let layout = self.case.layout(id)?;
        let types = archive_types();
        let listed = self.case.files_of_types(id, &types)?;
        let source = self.source.clone();
        let identifier = Identifier::new();
        let mut out = Vec::new();
        for (vol, fs) in layout.filesystems() {
            // Classified: the stored type decides (the classifier saw more of the file than the
            // head read here). Not classified: identify the head now.
            let wanted: Option<HashMap<usize, TypeId>> = listed.as_ref().map(|l| {
                l.iter().filter(|(v, _, _)| *v == vol.index).filter_map(|(_, i, ty)| Some((*i, type_by_name(ty)?))).collect()
            });
            let vol_source = vol.open(source.clone());
            for (idx, e) in fs.entries().iter().enumerate().filter(|(_, e)| !e.is_dir && e.size > 0) {
                let hint = match &wanted {
                    Some(w) => match w.get(&idx) {
                        Some(t) => *t,
                        None => continue,
                    },
                    None => {
                        let Ok(head) = ExtentReader::new(vol_source.as_ref(), e).read_all(HEAD_BYTES) else { continue };
                        let t = identifier.identify(&head, Some(&e.name)).file_type;
                        if ArchiveFormat::for_type(t).is_none() {
                            continue;
                        }
                        t
                    }
                };
                out.push(Self::file_target(vol.index, vol.range.start(), idx, e, Some(hint)));
            }
        }
        Ok(out)
    }

    fn file_target(volume: u32, volume_start: u64, file_idx: usize, e: &FileEntry, hint: Option<TypeId>) -> Target {
        let first = e.extents.first().and_then(|x| x.volume_offset).map_or(0, |o| volume_start + o);
        Target {
            name: e.path.clone(),
            volume: Some(volume),
            state: e.state,
            offset: first,
            size: e.size,
            hint,
            origin: Origin::File { volume, file_idx },
        }
    }

    /// Archives recorded by the carve step (`carve.unallocated` hits with an archive verdict).
    fn carved(&self, id: EvidenceId) -> Result<Vec<Target>> {
        let layout = self.case.layout(id)?;
        let q = HitQuery { evidence: Some(id), categories: vec![HitCategory::FileSignature], ..HitQuery::default() };
        let mut out = Vec::new();
        for h in self.case.hits(&q)?.into_iter().filter(|h| h.hit.detector == "carve.unallocated") {
            let mut d = h.hit.details.clone();
            if d.pointer("/verdict/category").and_then(|c| c.as_str()) != Some("archive") {
                continue;
            }
            d["file_type"] = d.pointer("/verdict/file_type").cloned().unwrap_or_default();
            let Ok(file) = serde_json::from_value::<CarvedFile>(d) else { continue };
            let hint = Some(file.verdict.file_type).filter(|t| ArchiveFormat::for_type(*t).is_some());
            let Some(hint) = hint.or_else(|| type_by_name(&file.verdict.type_name)) else { continue };
            out.push(Target {
                name: format!("$Carved/{}@{:#x}", hint.key(), file.range.start()),
                volume: layout.attribute(file.range.start()).volume,
                state: EntryState::Deleted,
                offset: file.range.start(),
                size: file.range.len(),
                hint: Some(hint),
                origin: Origin::Carved(Box::new(file)),
            });
        }
        Ok(out)
    }

    /// The archive's bytes (at most [`MAX_ARCHIVE_BYTES`]).
    pub fn read(&self, id: EvidenceId, t: &Target) -> Result<Vec<u8>> {
        let limit = MAX_ARCHIVE_BYTES as usize;
        match &t.origin {
            Origin::Carved(file) => Carver::new(self.source.clone()).read(file, limit),
            Origin::File { volume, file_idx } => {
                let layout = self.case.layout(id)?;
                let source = self.source.clone();
                let (vol, fs) = layout
                    .filesystems()
                    .find(|(v, _)| v.index == *volume)
                    .ok_or_else(|| strata_kernel::Error::Other(format!("volume {volume} not mounted")))?;
                let e = fs.entries().get(*file_idx).ok_or_else(|| strata_kernel::Error::Other(format!("{}: gone", t.name)))?;
                ExtentReader::new(vol.open(source).as_ref(), e).read_all(limit)
            }
        }
    }
}
