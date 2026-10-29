//! Cleaning and wiping programs installed, run or present as files, and third-party browsers
//! installed without any history left.

use super::Check;
use crate::catalog::{BROWSERS, Browser, TOOLS, Tool, ToolKind};
use crate::inputs::{DiskInputs, EntryState, ProgramTrace};
use crate::observation::{Observation, Severity, Signal};
use crate::units::{count, day};

pub(crate) struct CleaningCheck;

impl Check for CleaningCheck {
    fn observe(&self, disk: &DiskInputs, out: &mut Vec<Observation>) {
        out.extend(TOOLS.iter().filter_map(|t| tool(t, disk)));
        out.extend(BROWSERS.iter().filter_map(|b| browser(b, disk)));
    }
}

fn tool(tool: &Tool, disk: &DiskInputs) -> Option<Observation> {
    let rows: Vec<_> = disk.programs.iter().filter(|p| tool.names_title(&p.title)).collect();
    let files: Vec<_> = disk.named_files.iter().filter(|f| tool.names_file(f.name())).collect();
    if rows.is_empty() && files.is_empty() {
        return None;
    }
    let installed = rows.iter().filter(|p| p.trace == ProgramTrace::Installed).map(|p| p.first).min();
    let runs: Vec<_> = rows.iter().filter(|p| p.trace == ProgramTrace::Ran).collect();
    let last_run = runs.iter().map(|p| p.last).max();
    let run_count: u64 = runs.iter().map(|p| p.count).sum();
    let how = match (installed.is_some(), last_run.is_some()) {
        (true, true) => "installed and run",
        (true, false) => "installed",
        (false, true) => "run",
        (false, false) => "found",
    };
    let what = match tool.kind {
        ToolKind::Cleaner => {
            "It deletes browser history, temporary files, recent-document lists and logs. Expect gaps in the timeline and \
             fewer traces than the use of the computer would leave."
        }
        ToolKind::Wiper => {
            "It overwrites deleted files, free space or whole disks. What it was pointed at is unrecoverable, and free \
             space may hold far less than usual."
        }
    };
    let mut o = Observation::new(Severity::Warning, Signal::CleaningTool, format!("{} {how}", tool.name), what);
    if let Some(t) = installed {
        o = o.figure("Installed", day(t));
    }
    if let Some(t) = last_run {
        o = o.figure("Last run", day(t)).figure("Runs recorded", count(run_count));
    }
    if let Some(f) = files.iter().find(|f| f.state == EntryState::Live).or(files.first()) {
        let state = if f.state == EntryState::Live { "" } else { " (deleted)" };
        o = o.figure("File", format!("{}{state}", f.path)).on(f.volume);
    }
    Some(o)
}

fn browser(browser: &Browser, disk: &DiskInputs) -> Option<Observation> {
    let installed = disk.programs.iter().any(|p| p.trace == ProgramTrace::Installed && browser.names_title(&p.title))
        || disk.named_files.iter().any(|f| f.state == EntryState::Live && browser.names_file(f.name()));
    let history: u64 = disk.history.iter().filter(|h| browser.stores(&h.artifact)).map(|h| h.events).sum();
    (installed && history == 0).then(|| {
        Observation::new(
            Severity::Notice,
            Signal::BrowserWithoutHistory,
            format!("{} installed but no history", browser.name),
            format!(
                "{} is installed, but none of its history, cookies or saved logins were found. Its history was cleared, \
                 its profile deleted, or it was never used. Older history may survive in free space (see the URL findings).",
                browser.name
            ),
        )
    })
}
