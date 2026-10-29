//! The stored file listing: name search over every entry (deleted and orphaned ones too),
//! content types with renamed-extension alerts, and paths that differ between disks.

use crate::StrataServer;
use crate::format::{Page, Paging, Reply, fail, unix_time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{FileRow, TypeCount, Workbench};

/// Entries scanned when a state filter thins out a name search.
const FILTER_WINDOW: usize = 20_000;

/// Which entries a file search returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    #[default]
    Any,
    /// Allocated (not deleted).
    Live,
    Deleted,
    /// Entries whose parent folder is gone.
    Orphan,
}

impl FileState {
    fn keeps(self, state: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Live => state == "Allocated",
            Self::Deleted => state == "Deleted",
            Self::Orphan => state == "Orphan",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindFilesParams {
    /// Name to look for: `*` and `?` make it a glob over the whole name (`wallet*.dat`),
    /// otherwise any name containing it matches. Any case.
    pub pattern: String,
    /// Only this disk id.
    #[serde(default)]
    pub disk: Option<u32>,
    /// Default `any`.
    #[serde(default)]
    pub state: FileState,
    /// Rows per page, default 100, at most 1000. Deleted and orphaned entries come first.
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: usize,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FileTypesParams {
    /// Only this disk id.
    pub disk: Option<u32>,
    /// Renamed files per page, default 50, at most 500.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct FileComplementsParams {
    /// Rows per page, default 50, at most 500.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Serialize)]
struct FileOut {
    disk: u32,
    volume: u32,
    index: usize,
    path: String,
    name: String,
    size: u64,
    is_dir: bool,
    /// `Allocated`, `Deleted` or `Orphan`.
    state: String,
    created: Option<String>,
    modified: Option<String>,
    accessed: Option<String>,
    /// Content type found by the classify step.
    #[serde(skip_serializing_if = "Option::is_none")]
    detected_type: Option<String>,
    /// The extension does not match the content.
    renamed: bool,
}

impl FileOut {
    fn of(f: FileRow) -> Self {
        Self {
            disk: f.evidence.get(),
            volume: f.volume,
            index: f.file_idx,
            path: f.path,
            name: f.name,
            size: f.size,
            is_dir: f.is_dir,
            state: f.state,
            created: f.created.and_then(unix_time),
            modified: f.modified.and_then(unix_time),
            accessed: f.accessed.and_then(unix_time),
            detected_type: f.detected_type,
            renamed: f.extension_mismatch,
        }
    }
}

#[derive(Serialize)]
struct FileTypes {
    types: Vec<TypeCount>,
    renamed_files: Page<FileOut>,
}

#[derive(Serialize)]
struct Complement {
    path: String,
    copies: Vec<FileCopy>,
}

#[derive(Serialize)]
struct FileCopy {
    disk: u32,
    state: String,
    size: u64,
}

fn find(wb: &Workbench, p: FindFilesParams) -> Reply<Page<FileOut>> {
    if p.pattern.trim().is_empty() {
        return Err("give a name pattern, e.g. wallet.dat or *.key".into());
    }
    let limit = Paging::LONG.limit(p.limit);
    let fetch = if p.state == FileState::Any { p.offset + limit + 1 } else { FILTER_WINDOW };
    let rows: Vec<FileRow> = wb
        .find_files_by_name(&p.pattern, super::disk(p.disk), fetch)
        .map_err(fail)?
        .into_iter()
        .filter(|f| p.state.keeps(&f.state))
        .skip(p.offset)
        .take(limit + 1)
        .collect();
    Ok(Page::probed(rows, p.offset, limit).map(FileOut::of))
}

fn types(wb: &Workbench, p: FileTypesParams) -> Reply<FileTypes> {
    let limit = Paging::LIST.limit(p.limit);
    let renamed = wb.renamed_files(super::disk(p.disk), p.offset, limit + 1).map_err(fail)?;
    Ok(FileTypes { types: wb.type_counts(super::disk(p.disk)).map_err(fail)?, renamed_files: Page::probed(renamed, p.offset, limit).map(FileOut::of) })
}

fn complements(wb: &Workbench, p: FileComplementsParams) -> Reply<Page<Complement>> {
    let rows = wb
        .file_complements()
        .map_err(fail)?
        .into_iter()
        .map(|c| Complement { path: c.path, copies: c.copies.into_iter().map(|(e, state, size)| FileCopy { disk: e.get(), state, size }).collect() })
        .collect();
    Ok(Page::slice(rows, p.offset, Paging::LIST.limit(p.limit)))
}

#[tool_router(router = file_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Find files by name across all disks and volumes, deleted and orphaned entries included (they come first): \
        path, size, state, created/modified/accessed times, content type and renamed-extension flag. Example patterns: \
        wallet.dat, *.wallet, electrum*, seed."
    )]
    pub async fn find_files(&self, Parameters(p): Parameters<FindFilesParams>) -> Reply<String> {
        self.query(move |wb| find(wb, p)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Content types the classify step found (files per type, how many are renamed) and the list of renamed \
        files whose content does not match the extension, e.g. a wallet or archive saved as .jpg."
    )]
    pub async fn file_types(&self, Parameters(p): Parameters<FileTypesParams>) -> Reply<String> {
        self.query(move |wb| types(wb, p)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Files present on several disks in different states or sizes, e.g. deleted and overwritten on one drive \
        but intact on another backup drive."
    )]
    pub async fn file_complements(&self, Parameters(p): Parameters<FileComplementsParams>) -> Reply<String> {
        self.query(move |wb| complements(wb, p)).await
    }
}
