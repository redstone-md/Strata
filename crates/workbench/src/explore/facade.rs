//! Workbench use cases for exploring a disk: lost partitions, content search, file browsing,
//! previews and recovery. GUI and CLI call these; the work lives in the sibling modules.

use super::files::{DirNode, FileListQuery, FileListing, subdirs};
use super::partitions::{PartitionRecovery, PartitionReport};
use super::recovery::Recovered;
use crate::jobs::{JobId, JobKind};
use crate::steps::recover::RecoverCursor;
use crate::steps::search::SearchCursor;
use crate::workbench::Workbench;
use std::path::PathBuf;
use std::sync::Arc;
use strata_case::{EvidenceRecord, FileRow, FileTypes, SearchRecord, SearchResultRow, StoredHit, TypeCount};
use strata_fs::FileId;
use strata_kernel::{Error, EvidenceId, Result};
use strata_search::{SearchMatcher, SearchQuery};

impl Workbench {
    /// Add a disk and also run the deep partition sweep (old CHS layouts).
    pub fn add_evidence_deep(&self, location: &str) -> Result<EvidenceRecord> {
        self.case().add_evidence_deep(location)
    }

    /// Turn partition structures found by the deep scan into recovered volumes (foreground).
    pub fn recover_partitions(&self, evidence: EvidenceId) -> Result<PartitionReport> {
        PartitionRecovery::new(self.case()).run(evidence)
    }

    fn search_targets(&self, evidence: Option<EvidenceId>) -> Result<Vec<EvidenceId>> {
        Ok(match evidence {
            Some(id) => vec![id],
            None => self.evidence()?.into_iter().map(|e| e.id).collect(),
        })
    }

    /// Start a disk content search as a background job (it resumes after a crash like any
    /// other). Errors at once when the query cannot be compiled. Returns the job and the
    /// search id its results are stored under.
    pub fn start_search(self: &Arc<Self>, query: SearchQuery, evidence: Option<EvidenceId>) -> Result<(JobId, i64)> {
        SearchMatcher::compile(&query).map_err(Error::Other)?;
        let targets = self.search_targets(evidence)?;
        let first = *targets.first().ok_or_else(|| Error::Other("add a disk first".into()))?;
        let json = serde_json::to_string(&query).map_err(|e| Error::Other(e.to_string()))?;
        let search = self.case().begin_search(&json, &query.summary())?;
        let title = format!("Search {}", query.summary());
        let cursor = SearchCursor { search, query: Some(query), disks: targets.iter().map(|d| d.get()).collect(), ..SearchCursor::default() };
        Ok((self.start_job(JobKind::Search, first, &title, &cursor)?, search))
    }

    pub fn searches(&self, limit: usize) -> Result<Vec<SearchRecord>> {
        self.case().searches(limit)
    }

    pub fn search_record(&self, search: i64) -> Result<Option<SearchRecord>> {
        self.case().search_record(search)
    }

    pub fn search_results(&self, search: i64, offset: usize, limit: usize) -> Result<Vec<SearchResultRow>> {
        self.case().search_results(search, offset, limit)
    }

    /// File entries (deleted and orphaned included) whose name matches; `*`/`?` glob.
    pub fn find_files_by_name(&self, pattern: &str, evidence: Option<EvidenceId>, limit: usize) -> Result<Vec<FileRow>> {
        self.case().find_files_by_name(pattern, evidence, limit)
    }

    /// Files whose content does not match their extension, on every disk or one.
    pub fn renamed_files(&self, evidence: Option<EvidenceId>, offset: usize, limit: usize) -> Result<Vec<FileRow>> {
        self.case().renamed_files(evidence, offset, limit)
    }

    /// Files per content type from the classify step, most common first.
    pub fn type_counts(&self, evidence: Option<EvidenceId>) -> Result<Vec<TypeCount>> {
        self.case().type_counts(evidence)
    }

    /// Content types from the classify step, for [`Workbench::list_files`].
    pub fn file_types(&self, evidence: EvidenceId) -> Result<Arc<FileTypes>> {
        Ok(Arc::new(self.case().file_types(evidence)?))
    }

    /// Subfolders of a folder (`None` = volume root), for the tree pane.
    pub fn subdirs(&self, evidence: EvidenceId, volume: u32, dir: Option<usize>) -> Result<Vec<DirNode>> {
        let layout = self.case().layout(evidence)?;
        Ok(layout.filesystem(volume).map(|(_, fs)| subdirs(fs, dir)).unwrap_or_default())
    }

    pub fn list_files(&self, q: &FileListQuery, types: Arc<FileTypes>) -> Result<FileListing> {
        Ok(FileListing::build(self.case().layout(q.evidence)?, types, q))
    }

    /// Full path of one entry (`""` for a volume root).
    pub fn entry_path(&self, evidence: EvidenceId, volume: u32, index: usize) -> Option<String> {
        let layout = self.case().layout(evidence).ok()?;
        let (_, fs) = layout.filesystem(volume)?;
        fs.entry(FileId::new(index)).map(|e| e.path.clone())
    }

    /// Up to `len` bytes of a file's content from `offset` (overwritten parts as they are now).
    pub fn read_file(&self, evidence: EvidenceId, volume: u32, index: usize, offset: u64, len: usize) -> Result<Vec<u8>> {
        let layout = self.case().layout(evidence)?;
        let (_, fs) = layout.filesystem(volume).ok_or_else(|| Error::Other(format!("volume {volume} did not parse")))?;
        let mut buf = vec![0u8; len];
        let n = fs.read(FileId::new(index), offset, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Raw disk bytes.
    pub fn read_disk(&self, evidence: EvidenceId, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.case().source(evidence)?.read_vec(offset, len)
    }

    /// Copy files and folders (entry indexes of one volume) to `dest` as a background job
    /// that resumes after a crash with the next item.
    pub fn recover_files(self: &Arc<Self>, evidence: EvidenceId, volume: u32, selection: Vec<usize>, dest: PathBuf) -> Result<JobId> {
        let title = format!("Recover {} to {}", super::recovery::count_label(selection.len()), dest.display());
        let cursor = RecoverCursor { volume, selection, dest, ..RecoverCursor::default() };
        self.start_job(JobKind::Recover, evidence, &title, &cursor)
    }

    /// Write a carved file or archive member behind a finding to `dest`.
    pub fn export_finding(&self, hit: &StoredHit, dest: &std::path::Path) -> Result<Recovered> {
        super::recovery::export(self.case(), hit, dest)
    }
}
