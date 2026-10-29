//! Machine profiles and usage periods: the case's host facts and user activity, read with the
//! machines context's own filters and handed to it.

use crate::Workbench;
use std::time::SystemTime;
use strata_case::{EventFilter, FactGroup, TitledEvents};
use strata_kernel::{EvidenceId, Result, Timestamp};
use strata_machines::{
    ActivityKind, ActivityRow, DiskInputs, DiskMachines, FactRow, LogonRow, NOT_ACTIVITY_PREFIXES, POWER_TITLE_INFIXES, POWER_TITLE_PREFIXES,
    PROFILE_KEYS, ProgramEvidence, ProgramRow, UsageReport, UsageWindow,
};
use strata_timeline::EventKind;

/// Title words of program runs worth checking against the wallet and miner catalogue (the
/// rest of a shell history or prefetch folder is not).
const PROGRAM_HINTS: &[&str] = &["coin", "miner", "wallet", "electrum", "armory", "exodus", "jaxx", "ledger", "trezor"];
/// Slack after the image date: clocks and time zones are not exact.
const WINDOW_SLACK_SECS: i64 = 86_400;

fn kind_name(kind: EventKind) -> String {
    format!("{kind:?}")
}

fn kind_of(name: &str) -> Option<EventKind> {
    EventKind::ALL.into_iter().find(|k| kind_name(*k) == name)
}

fn names(kinds: &[EventKind]) -> Vec<String> {
    kinds.iter().map(|k| kind_name(*k)).collect()
}

fn refs(items: &[String]) -> Vec<&str> {
    items.iter().map(String::as_str).collect()
}

impl Workbench {
    /// One profile per operating-system installation on the disk, with when each (and the
    /// disk as a whole) was in use.
    pub fn machines(&self, evidence: EvidenceId) -> Result<DiskMachines> {
        Ok(DiskMachines::build(&self.machine_inputs(evidence)?))
    }

    /// When the disk was in use (all installations together).
    pub fn disk_usage(&self, evidence: EvidenceId) -> Result<UsageReport> {
        Ok(self.machines(evidence)?.usage)
    }

    /// Host facts grouped by key, each with its `per_key` most frequent distinct values.
    pub fn fact_groups(&self, evidence: EvidenceId, per_key: usize) -> Result<Vec<FactGroup>> {
        self.case.fact_groups(evidence, per_key)
    }

    fn machine_inputs(&self, evidence: EvidenceId) -> Result<DiskInputs> {
        let facts = self
            .case
            .facts_with_keys(evidence, PROFILE_KEYS)?
            .into_iter()
            .map(|f| FactRow { volume: f.volume, key: f.key, value: f.value, artifact: f.artifact, source: f.source })
            .collect();
        let (kinds, power) = (names(ActivityKind::EVENT_KINDS), names(ActivityKind::POWER_KINDS));
        let activity_filter = EventFilter {
            kinds: &refs(&kinds),
            titled_kinds: &refs(&power),
            title_prefixes: POWER_TITLE_PREFIXES,
            title_infixes: POWER_TITLE_INFIXES,
            or_crypto: false,
            excluded_prefixes: NOT_ACTIVITY_PREFIXES,
        };
        let activity = self
            .case
            .hourly_events(evidence, &activity_filter)?
            .into_iter()
            .filter_map(|h| {
                let kind = ActivityKind::of_kind(kind_of(&h.kind)?)?;
                Some(ActivityRow { volume: h.volume, path: h.path, kind, hour: h.hour, count: h.count })
            })
            .collect();
        let logon = [kind_name(EventKind::Login)];
        let logon_filter = EventFilter { kinds: &refs(&logon), excluded_prefixes: NOT_ACTIVITY_PREFIXES, ..Default::default() };
        let logons = self
            .case
            .titled_events(evidence, &logon_filter)?
            .into_iter()
            .map(|e| LogonRow { volume: e.volume, path: e.path, title: e.title, last: e.last, count: e.count })
            .collect();
        let installed = [kind_name(EventKind::ProgramInstalled)];
        let used = names(&[EventKind::ProgramRun, EventKind::WalletActivity]);
        let program_filter = EventFilter {
            kinds: &refs(&installed),
            titled_kinds: &refs(&used),
            title_infixes: PROGRAM_HINTS,
            or_crypto: true,
            ..Default::default()
        };
        let programs = self.case.titled_events(evidence, &program_filter)?.into_iter().filter_map(program_row).collect();
        Ok(DiskInputs { facts, activity, logons, programs, window: self.usage_window(evidence) })
    }

    /// 1995 up to the image file's date (when the evidence is a file) or today.
    fn usage_window(&self, evidence: EvidenceId) -> UsageWindow {
        let secs = |t: SystemTime| t.duration_since(SystemTime::UNIX_EPOCH).ok().map(|d| d.as_secs() as i64);
        let now = secs(SystemTime::now()).unwrap_or(i64::MAX / 2);
        let image = self
            .case
            .record(evidence)
            .ok()
            .and_then(|r| std::fs::metadata(&r.info.location).ok())
            .filter(|m| m.is_file())
            .and_then(|m| m.modified().ok())
            .and_then(secs);
        let until = image.map_or(now, |i| i.min(now)).saturating_add(WINDOW_SLACK_SECS);
        Timestamp::from_unix_secs(until).map_or_else(UsageWindow::default, UsageWindow::until)
    }
}

fn program_row(e: TitledEvents) -> Option<ProgramRow> {
    let evidence = match kind_of(&e.kind)? {
        EventKind::ProgramInstalled => ProgramEvidence::Installed,
        EventKind::ProgramRun => ProgramEvidence::Ran,
        EventKind::WalletActivity => ProgramEvidence::WalletTrace,
        _ => return None,
    };
    Some(ProgramRow {
        volume: e.volume,
        path: e.path,
        artifact: e.artifact,
        evidence,
        title: e.title,
        first: e.first,
        last: e.last,
        count: e.count,
        crypto: e.crypto,
    })
}
