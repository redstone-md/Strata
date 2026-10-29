//! Ownership signals per identity, gathered from the facts before any node exists, and the
//! noise rule built on them: an identity nobody uses (no artefact, no live mail, no key next
//! to it, no money account) that only lives in system files or in hundreds of files is left out.

use crate::facts::{Facts, FindingFact, SpreadFact};
use crate::paths::{self, PathClass};
use crate::rank::Ownership;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use strata_kernel::EvidenceId;
use strata_kernel::scan::HitCategory;

/// An identity in this many files without any sign of use is broadcast text (lists, dumps).
pub(crate) const BROADCAST_FILES: u64 = 300;
/// Least live messages on a disk before its most frequent recipient counts as the mailbox owner.
const MIN_MAILBOX: u64 = 3;

pub(crate) struct Signals {
    by_value: HashMap<String, Ownership>,
    spreads: HashMap<String, SpreadFact>,
    /// Identities with an account on a service that holds funds or deals in coins.
    money_accounts: BTreeSet<String>,
    none: Ownership,
}

fn fold(v: &str) -> String {
    v.trim().to_lowercase()
}

impl Signals {
    pub fn collect(facts: &Facts) -> Self {
        let mut by_value: HashMap<String, Ownership> = HashMap::new();
        let mut profiles = BTreeSet::new();
        let mut placed_outside_system = BTreeSet::new();
        for f in &facts.findings {
            if let Some(name) = f.file.as_deref().and_then(paths::profile_name) {
                profiles.insert(name);
            }
            if f.category != HitCategory::Identity {
                continue;
            }
            let o = by_value.entry(fold(&f.value)).or_default();
            if f.from_artefact() && o.artefact.is_none() {
                o.artefact = Some(f.detail.clone().unwrap_or_else(|| f.label.clone()));
            }
            if let Some(path) = &f.file {
                Self::place(o, paths::classify(path));
                if paths::classify(path) != PathClass::System {
                    placed_outside_system.insert(fold(&f.value));
                }
            }
        }
        Self::next_to_secrets(facts, &mut by_value);
        Self::mail(facts, &mut by_value);
        let mut spreads = HashMap::new();
        for s in &facts.spreads {
            let value = fold(&s.value);
            let classes: Vec<PathClass> = s.sample_paths.iter().map(|p| paths::classify(p)).collect();
            profiles.extend(s.sample_paths.iter().filter_map(|p| paths::profile_name(p)));
            let o = by_value.entry(value.clone()).or_default();
            classes.iter().for_each(|c| Self::place(o, *c));
            o.system_only = !classes.is_empty() && classes.iter().all(|c| *c == PathClass::System) && !placed_outside_system.contains(&value);
            spreads.insert(value, s.clone());
        }
        for (value, o) in by_value.iter_mut() {
            let local = value.split('@').next().unwrap_or(value);
            o.profile_name = local.len() >= 3 && profiles.contains(local);
        }
        let money_accounts = facts
            .accounts
            .iter()
            .filter(|a| a.service_kind().is_some_and(|k| k.holds_funds() || k.is_crypto()))
            .map(|a| fold(a.identifier()))
            .collect();
        Self { by_value, spreads, money_accounts, none: Ownership::default() }
    }

    fn place(o: &mut Ownership, class: PathClass) {
        match class {
            PathClass::Browser => o.in_browser = true,
            PathClass::MailClient => o.in_mail_client = true,
            PathClass::Profile => o.in_profile = true,
            _ => {}
        }
        o.in_profile |= class >= PathClass::Profile;
    }

    /// Identities sharing a file with a key, seed or wallet.
    fn next_to_secrets(facts: &Facts, by_value: &mut HashMap<String, Ownership>) {
        let mut files: BTreeMap<(EvidenceId, &str), Vec<&FindingFact>> = BTreeMap::new();
        for f in &facts.findings {
            if let Some(path) = &f.file {
                files.entry((f.disk, path.as_str())).or_default().push(f);
            }
        }
        for ((_, path), group) in files {
            if !group.iter().any(|f| f.is_secret()) {
                continue;
            }
            for f in group.iter().filter(|f| f.category == HitCategory::Identity) {
                by_value.entry(fold(&f.value)).or_default().next_to_secret.get_or_insert_with(|| paths::file_name(path).to_string());
            }
        }
    }

    /// Live mail: who sends and receives, and per disk the address most of it goes to.
    fn mail(facts: &Facts, by_value: &mut HashMap<String, Ownership>) {
        let mut per_disk: BTreeMap<EvidenceId, (u64, BTreeMap<&str, u64>)> = BTreeMap::new();
        for m in facts.mail.iter().filter(|m| m.live) {
            for a in &m.from {
                by_value.entry(fold(a)).or_default().live_sent += 1;
            }
            let disk = per_disk.entry(m.disk).or_default();
            disk.0 += 1;
            for a in &m.to {
                by_value.entry(fold(a)).or_default().live_received += 1;
                *disk.1.entry(a.as_str()).or_default() += 1;
            }
        }
        for (total, counts) in per_disk.values() {
            let best = counts.iter().max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)));
            if let Some((address, _)) = best.filter(|(_, n)| **n >= MIN_MAILBOX && **n * 10 >= *total * 3) {
                by_value.entry(fold(address)).or_default().mailbox_owner = true;
            }
        }
    }

    pub fn of(&self, value: &str) -> &Ownership {
        self.by_value.get(&fold(value)).unwrap_or(&self.none)
    }

    pub fn spread(&self, value: &str) -> Option<&SpreadFact> {
        self.spreads.get(&fold(value))
    }

    /// Leave this identity out of the graph.
    pub fn is_noise(&self, value: &str) -> bool {
        let o = self.of(value);
        let used = o.artefact.is_some() || o.live_received > 0 || o.live_sent > 0 || o.next_to_secret.is_some() || o.profile_name;
        if used || self.money_accounts.contains(&fold(value)) {
            return false;
        }
        o.system_only || self.spread(value).is_some_and(|s| s.files >= BROADCAST_FILES)
    }
}
