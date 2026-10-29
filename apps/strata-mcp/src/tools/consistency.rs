//! Evidence consistency per disk: whether what Strata extracted is plausible (normally used,
//! little use, wiped or reinstalled, file system not fully read) and the observations behind
//! the verdict, each with a plain explanation and its numbers.

use crate::StrataServer;
use crate::format::{Reply, fail};
use crate::tools::machines::disks;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{Observation, Severity, Workbench};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ConsistencyParams {
    /// Only this disk id.
    pub disk: Option<u32>,
    /// Leave out context-only observations (format and install dates, last activity).
    pub skip_info: bool,
}

#[derive(Serialize)]
struct ObservationOut {
    /// info, notice, warning or alert.
    severity: &'static str,
    signal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    volume: Option<u32>,
    title: String,
    explanation: String,
    /// The numbers behind it, as `[label, value]`.
    figures: Vec<(String, String)>,
}

impl ObservationOut {
    fn of(o: &Observation) -> Self {
        Self {
            severity: o.severity.label(),
            signal: serde_json::to_value(o.signal).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(),
            volume: o.volume,
            title: o.title.clone(),
            explanation: o.explanation.clone(),
            figures: o.figures.iter().map(|f| (f.label.clone(), f.value.clone())).collect(),
        }
    }
}

#[derive(Serialize)]
struct DiskConsistency {
    disk: u32,
    label: String,
    /// NotAnalysed, NormallyUsed, LittleUse, WipedOrReinstalled or Unreadable.
    verdict: String,
    headline: String,
    observations: Vec<ObservationOut>,
}

fn consistency(wb: &Workbench, p: ConsistencyParams) -> Reply<Vec<DiskConsistency>> {
    let floor = if p.skip_info { Severity::Notice } else { Severity::Info };
    disks(wb, p.disk)?
        .into_iter()
        .map(|(id, label)| {
            let a = wb.consistency(id).map_err(fail)?;
            Ok(DiskConsistency {
                disk: id.get(),
                label,
                verdict: format!("{:?}", a.verdict.kind),
                headline: a.verdict.headline.clone(),
                observations: a.at_least(floor).map(ObservationOut::of).collect(),
            })
        })
        .collect()
}

#[tool_router(router = consistency_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Whether what Strata extracted from each disk is plausible, judged from the case alone (no disk reads): \
        a verdict (NormallyUsed, LittleUse, WipedOrReinstalled with a date when known, Unreadable when Strata could not read \
        a file system, NotAnalysed before indexing) and observations most severe first. Signals: file index size against the \
        volume (a 320 GB volume listing 24 files is flagged), NTFS MFT room against records read, volumes not listed or not \
        recognised, deleted and orphaned files, format and install dates against user activity, Windows.old, little use, long \
        gaps, empty user folders, cleaning and wiping tools (CCleaner, Eraser, SDelete, DBAN...), browsers installed without \
        history, and findings lying outside files. Check this before trusting that a disk holds nothing."
    )]
    pub async fn consistency(&self, Parameters(p): Parameters<ConsistencyParams>) -> Reply<String> {
        self.query(move |wb| consistency(wb, p)).await
    }
}
