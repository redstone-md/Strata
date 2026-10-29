//! Evidence consistency: the case's file index tallies, a few named files, program and
//! history events, finding placement and the machines context's installations and usage,
//! read with the consistency context's own folders, names and words and handed to it.

use crate::Workbench;
use crate::jobs::JobKind;
use std::collections::BTreeMap;
use strata_case::{EventFilter, FileTally, IndexedFile};
use strata_consistency::catalog::{file_stems, program_words};
use strata_consistency::{
    ActiveSpan, Activity, Assessment, DiskInputs, EntryState, FileTable, HistoryCount, HitPlacement, Installation, MFT_PATH, NamedFile,
    PREVIOUS_WINDOWS, PROFILE_ROOTS, ProfileFolder, ProgramRow, ProgramTrace, Tally, VolumeInputs,
};
use strata_kernel::scan::HitCategory;
use strata_kernel::{EvidenceId, Result};
use strata_machines::{DiskMachines, InstallKind, UsageReport};
use strata_timeline::EventKind;
use strata_volume::{FsKind, VolumeOrigin};

/// Files named like a cleaning tool or browser read at most (a handful is plenty).
const NAMED_FILES: usize = 200;
/// Event kinds browsers store; none of them for an installed browser means no history.
const BROWSING_KINDS: &[EventKind] = &[EventKind::UrlVisited, EventKind::Download, EventKind::Search, EventKind::FormInput, EventKind::Cookie];
/// Finding categories that say nothing about where data lies (partition records, renamed
/// file types).
const PLACEMENT_SKIPPED: &[HitCategory] = &[HitCategory::Partition, HitCategory::FileSignature];

impl Workbench {
    /// Whether what was extracted from the disk is plausible: a verdict (normally used, little
    /// use, wiped or reinstalled, not fully read) with the observations behind it.
    pub fn consistency(&self, evidence: EvidenceId) -> Result<Assessment> {
        let machines = self.machines(evidence)?;
        self.consistency_with(evidence, &machines)
    }

    /// [`Workbench::consistency`] reusing machines already built for the disk.
    pub fn consistency_with(&self, evidence: EvidenceId, machines: &DiskMachines) -> Result<Assessment> {
        Ok(Assessment::of(&self.consistency_inputs(evidence, machines)?))
    }

    fn consistency_inputs(&self, evidence: EvidenceId, machines: &DiskMachines) -> Result<DiskInputs> {
        let record = self.case.record(evidence)?;
        let tallies = self.case.file_tallies(evidence)?;
        let tables = self.case.files_at(evidence, &[MFT_PATH])?;
        let previous = self.case.folder_tallies(evidence, &[PREVIOUS_WINDOWS])?;
        let volumes = record
            .volumes
            .iter()
            .map(|v| {
                let mut input = VolumeInputs {
                    index: v.index,
                    fs: v.fs.name().to_string(),
                    recognised: v.fs != FsKind::Unknown,
                    len: v.range.len(),
                    recovered: v.origin == VolumeOrigin::Recovered,
                    live: Tally::default(),
                    deleted: Tally::default(),
                    orphan: Tally::default(),
                    folders: 0,
                    file_table: tables.iter().find(|t| t.volume == v.index).map(|t| FileTable { bytes: t.size, created: t.created }),
                    previous_windows: previous.iter().filter(|p| p.volume == v.index).map(|p| p.files).sum(),
                };
                for t in tallies.iter().filter(|t| t.volume == v.index) {
                    add_tally(&mut input, t);
                }
                input
            })
            .collect();
        let indexed = self.case.finished_jobs(evidence, JobKind::IndexFiles.name())? > 0 || !tallies.is_empty();
        Ok(DiskInputs {
            disk_len: record.info.len,
            indexed,
            volumes,
            profiles: self.profile_folders(evidence)?,
            programs: self.cleaning_programs(evidence)?,
            named_files: self.case.files_named_like(evidence, &file_stems(), NAMED_FILES)?.into_iter().map(named_file).collect(),
            history: self.browsing_history(evidence)?,
            hits: self.hit_placement(evidence)?,
            activity: activity(&machines.usage),
            installations: machines
                .machines
                .iter()
                .filter(|m| matches!(m.profile.kind, InstallKind::System | InstallKind::Previous))
                .map(|m| Installation {
                    label: m.profile.os.product.value().cloned().unwrap_or_else(|| m.profile.family().to_string()),
                    volume: m.profile.key.volume,
                    installed: m.profile.os.install_date.value().map(|w| w.0),
                    previous: m.profile.kind == InstallKind::Previous,
                    activity: activity(&m.usage),
                })
                .collect(),
        })
    }

    fn profile_folders(&self, evidence: EvidenceId) -> Result<Vec<ProfileFolder>> {
        let mut folders: BTreeMap<(u32, String), ProfileFolder> = BTreeMap::new();
        for t in self.case.folder_tallies(evidence, PROFILE_ROOTS)? {
            let folder = folders.entry((t.volume, format!("{}{}", t.root, t.child))).or_insert_with(|| ProfileFolder {
                volume: t.volume,
                user: t.child.clone(),
                live: Tally::default(),
                deleted: Tally::default(),
            });
            match EntryState::parse(&t.state) {
                EntryState::Live => folder.live.add(Tally::new(t.files, t.bytes)),
                EntryState::Deleted | EntryState::Orphan => folder.deleted.add(Tally::new(t.files, t.bytes)),
            }
        }
        Ok(folders.into_values().collect())
    }

    fn cleaning_programs(&self, evidence: EvidenceId) -> Result<Vec<ProgramRow>> {
        let kinds = [format!("{:?}", EventKind::ProgramInstalled), format!("{:?}", EventKind::ProgramRun)];
        let words = program_words();
        let filter = EventFilter { titled_kinds: &[&kinds[0], &kinds[1]], title_infixes: &words, ..Default::default() };
        Ok(self
            .case
            .titled_events(evidence, &filter)?
            .into_iter()
            .map(|e| ProgramRow {
                trace: if e.kind == kinds[0] { ProgramTrace::Installed } else { ProgramTrace::Ran },
                title: e.title,
                first: e.first,
                last: e.last,
                count: e.count,
            })
            .collect())
    }

    fn browsing_history(&self, evidence: EvidenceId) -> Result<Vec<HistoryCount>> {
        let kinds: Vec<String> = BROWSING_KINDS.iter().map(|k| format!("{k:?}")).collect();
        let refs: Vec<&str> = kinds.iter().map(String::as_str).collect();
        Ok(self.case.event_counts_by_artifact(evidence, &refs)?.into_iter().map(|(artifact, events)| HistoryCount { artifact, events }).collect())
    }

    fn hit_placement(&self, evidence: EvidenceId) -> Result<HitPlacement> {
        let skipped: Vec<String> = PLACEMENT_SKIPPED.iter().map(|c| format!("{c:?}")).collect();
        let refs: Vec<&str> = skipped.iter().map(String::as_str).collect();
        let mut out = HitPlacement::default();
        for t in self.case.hit_placement(evidence, Self::NOISE_FLOOR, &refs)? {
            match t.state.as_deref().map(EntryState::parse) {
                None => out.free += t.count,
                Some(EntryState::Live) => out.live += t.count,
                Some(EntryState::Deleted | EntryState::Orphan) => out.deleted += t.count,
            }
        }
        Ok(out)
    }
}

fn add_tally(v: &mut VolumeInputs, t: &FileTally) {
    v.folders += t.folders;
    let tally = Tally::new(t.files, t.bytes);
    match EntryState::parse(&t.state) {
        EntryState::Live => v.live.add(tally),
        EntryState::Deleted => v.deleted.add(tally),
        EntryState::Orphan => v.orphan.add(tally),
    }
}

fn named_file(f: IndexedFile) -> NamedFile {
    NamedFile { volume: f.volume, state: EntryState::parse(&f.state), path: f.path }
}

fn activity(u: &UsageReport) -> Activity {
    Activity {
        first_day: u.first_day.map(|w| w.0),
        last_day: u.last_day.map(|w| w.0),
        active_days: u.active_days,
        events: u.events,
        periods: u.periods.iter().map(|p| ActiveSpan { from: p.from.0, to: p.to.0, active_days: p.active_days }).collect(),
    }
}
