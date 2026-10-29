//! One disk's machines: group every fact and activity row by the installation its file belongs
//! to, fold installations without identity of their own (a `/home` volume, a profile folder on
//! a data volume) into the one system of the same family, then build each profile and its usage.

use crate::location::{InstallKey, InstallKind, Location};
use crate::profile::{MachineProfile, ProfileBuilder};
use crate::software::ProgramRow;
use crate::usage::{ActivityRow, UsageAnalyzer, UsageReport, UsageWindow};
use serde::Serialize;
use std::collections::BTreeMap;
use strata_artifacts::host::keys;
use strata_kernel::Timestamp;

/// Fact keys that identify an installation (as opposed to traces found in a profile folder).
const IDENTITY_KEYS: &[&str] = &[keys::COMPUTER_NAME, keys::WINDOWS_PRODUCT, keys::LINUX_DISTRO, keys::INSTALL_DATE, keys::TIMEZONE_BIAS];

/// One stored host fact.
#[derive(Debug, Clone)]
pub struct FactRow {
    pub volume: Option<u32>,
    pub key: String,
    pub value: String,
    pub artifact: String,
    /// Evidence file path.
    pub source: String,
}

/// Logon events of one title from one file, aggregated.
#[derive(Debug, Clone)]
pub struct LogonRow {
    pub volume: Option<u32>,
    pub path: String,
    pub title: String,
    pub last: Timestamp,
    pub count: u64,
}

/// Everything the machines context reads for one disk.
#[derive(Debug, Clone)]
pub struct DiskInputs {
    pub facts: Vec<FactRow>,
    pub activity: Vec<ActivityRow>,
    pub logons: Vec<LogonRow>,
    pub programs: Vec<ProgramRow>,
    pub window: UsageWindow,
}

/// A profile and when that installation was used.
#[derive(Debug, Clone, Serialize)]
pub struct Machine {
    pub profile: MachineProfile,
    pub usage: UsageReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskMachines {
    /// Usage of the whole disk (every installation and unplaced activity).
    pub usage: UsageReport,
    pub machines: Vec<Machine>,
}

/// Groups of one disk: installation → kind and whether it carries identity facts.
struct Groups {
    kinds: BTreeMap<InstallKey, InstallKind>,
    identified: Vec<InstallKey>,
}

impl Groups {
    fn note(&mut self, key: &InstallKey, kind: InstallKind) {
        let k = self.kinds.entry(key.clone()).or_insert(kind);
        *k = (*k).min(kind);
    }

    /// Where rows of `key` end up: itself, or the single identified system of its family.
    fn target(&self, key: &InstallKey) -> InstallKey {
        if self.identified.contains(key) || !matches!(self.kinds.get(key), Some(InstallKind::System | InstallKind::HomeVolume)) {
            return key.clone();
        }
        let systems: Vec<&InstallKey> =
            self.identified.iter().filter(|k| k.family == key.family && self.kinds.get(*k) == Some(&InstallKind::System)).collect();
        match systems.as_slice() {
            [only] => (*only).clone(),
            _ => key.clone(),
        }
    }
}

/// Profile builders by target installation.
struct Assembly {
    groups: Groups,
    builders: BTreeMap<InstallKey, ProfileBuilder>,
}

impl Assembly {
    /// The builder a file's rows go to, and where the file sits.
    fn builder(&mut self, volume: Option<u32>, path: &str) -> Option<(&mut ProfileBuilder, Location)> {
        let (key, loc) = place(volume, path)?;
        let target = self.groups.target(&key);
        let kind = self.groups.kinds.get(&target).copied().unwrap_or(loc.kind);
        let b = self.builders.entry(target.clone()).or_insert_with(|| ProfileBuilder::new(target, kind));
        Some((b, loc))
    }
}

fn place(volume: Option<u32>, path: &str) -> Option<(InstallKey, Location)> {
    let loc = Location::of(path)?;
    Some((loc.key(volume), loc))
}

impl DiskMachines {
    pub fn build(inputs: &DiskInputs) -> Self {
        let mut groups = Groups { kinds: BTreeMap::new(), identified: Vec::new() };
        let paths = inputs
            .facts
            .iter()
            .map(|f| (f.volume, f.source.as_str()))
            .chain(inputs.activity.iter().map(|r| (r.volume, r.path.as_str())))
            .chain(inputs.logons.iter().map(|r| (r.volume, r.path.as_str())))
            .chain(inputs.programs.iter().map(|r| (r.volume, r.path.as_str())));
        for (volume, path) in paths {
            if let Some((key, loc)) = place(volume, path) {
                groups.note(&key, loc.kind);
            }
        }
        for f in inputs.facts.iter().filter(|f| IDENTITY_KEYS.contains(&f.key.as_str())) {
            if let Some((key, _)) = place(f.volume, &f.source)
                && !groups.identified.contains(&key)
            {
                groups.identified.push(key);
            }
        }
        let window = inputs.window;
        let mut at = Assembly { groups, builders: BTreeMap::new() };
        let mut activity: BTreeMap<InstallKey, Vec<&ActivityRow>> = BTreeMap::new();
        for r in &inputs.activity {
            let Some((b, loc)) = at.builder(r.volume, &r.path) else { continue };
            if let (Some(user), Some(t)) = (loc.user, r.at().filter(|t| window.contains(*t))) {
                b.user_activity(&user, t);
            }
            activity.entry(b.key().clone()).or_default().push(r);
        }
        for f in &inputs.facts {
            if let Some((b, _)) = at.builder(f.volume, &f.source) {
                b.fact(f);
            }
        }
        for r in inputs.logons.iter().filter(|r| window.contains(r.last)) {
            if let Some((b, _)) = at.builder(r.volume, &r.path) {
                b.logon(&r.title, r.last, r.count);
            }
        }
        for r in inputs.programs.iter().filter(|r| window.contains(r.first)) {
            if let Some((b, _)) = at.builder(r.volume, &r.path) {
                b.program(r);
            }
        }
        let mut machines: Vec<Machine> = at
            .builders
            .into_values()
            .map(|b| {
                let profile = b.finish();
                let bias = profile.time_zone.bias_minutes.value().copied();
                let rows = activity.remove(&profile.key).unwrap_or_default();
                let usage = UsageAnalyzer::new(window, bias).analyze(rows);
                Machine { profile, usage }
            })
            .filter(|m| m.profile.facts > 0 || !m.usage.is_empty())
            .collect();
        // Systems before copies and containers; identified before anonymous ones.
        machines.sort_by(|a, b| {
            let rank = |m: &Machine| (m.profile.kind, m.profile.computer_name.is_empty(), m.profile.key.clone());
            rank(a).cmp(&rank(b))
        });
        let biases: Vec<i32> = machines.iter().filter_map(|m| m.profile.time_zone.bias_minutes.value().copied()).collect();
        let disk_bias = biases.first().copied().filter(|b| biases.iter().all(|x| x == b));
        let usage = UsageAnalyzer::new(window, disk_bias).analyze(&inputs.activity);
        DiskMachines { usage, machines }
    }
}
