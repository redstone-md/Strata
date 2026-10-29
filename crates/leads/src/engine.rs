use crate::inputs::{KeyFinding, LeadInputs};
use crate::lead::Lead;
use crate::rules;
use crate::scoring::{RuleSpec, decay, days_between, signal_weight};
use crate::signal::{Signal, SignalClass};
use std::collections::HashMap;
use strata_accounts::{Service, ServiceKind};
use strata_kernel::{EvidenceId, Timestamp};

/// Correlates on-chain activity, timeline signals, accounts and key-file times into ranked
/// [`Lead`]s. Pure: the same inputs always give the same leads.
pub struct LeadEngine {
    min_score: f32,
    max_leads: usize,
}

impl Default for LeadEngine {
    fn default() -> Self {
        Self { min_score: 5.0, max_leads: 2_000 }
    }
}

impl LeadEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_min_score(mut self, min: f32) -> Self {
        self.min_score = min;
        self
    }

    pub fn run(&self, inputs: &LeadInputs) -> Vec<Lead> {
        let ctx = Context::new(inputs);
        let mut leads: Vec<Lead> = Vec::new();
        leads.extend(rules::onchain::run(&ctx));
        leads.extend(rules::after_install::run(&ctx));
        leads.extend(rules::wallet_window::run(&ctx));
        leads.extend(rules::account_check::run(&ctx));
        leads.extend(rules::gaps::run(&ctx));
        leads.retain(|l| l.score >= self.min_score);
        leads.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
        leads.dedup_by(|a, b| a.id == b.id);
        leads.truncate(self.max_leads);
        leads
    }
}

/// A period of use of one fund-holding service, from visits and account traces.
pub(crate) struct ServiceWindow {
    pub service: Service,
    pub first: Timestamp,
    pub last: Timestamp,
    pub traces: usize,
    pub events: Vec<i64>,
    pub evidence: Vec<EvidenceId>,
}

/// Up to three best supporting signals near a moment, and their combined strength.
pub(crate) struct Support<'a> {
    pub signals: Vec<(&'a Signal, f32)>,
    /// Noisy-or of the contributions, 0..=1.
    pub total: f32,
}

pub(crate) struct Context<'a> {
    pub inputs: &'a LeadInputs,
    /// Sorted by time.
    pub signals: Vec<Signal>,
    pub keys_by_address: HashMap<&'a str, Vec<&'a KeyFinding>>,
    pub windows: Vec<ServiceWindow>,
}

impl<'a> Context<'a> {
    fn new(inputs: &'a LeadInputs) -> Self {
        let mut signals: Vec<Signal> = inputs.events.iter().filter_map(Signal::of).collect();
        signals.sort_by_key(|s| (s.at, s.event_id));
        let mut keys_by_address: HashMap<&str, Vec<&KeyFinding>> = HashMap::new();
        for k in &inputs.keys {
            for a in &k.addresses {
                keys_by_address.entry(a.as_str()).or_default().push(k);
            }
        }
        let windows = service_windows(&signals, inputs);
        Self { inputs, signals, keys_by_address, windows }
    }

    /// Signals within `max_days` of `at`.
    pub fn near(&self, at: Timestamp, max_days: i64) -> &[Signal] {
        let (from, to) = (at.unix_secs() - max_days * 86_400, at.unix_secs() + max_days * 86_400);
        let lo = self.signals.partition_point(|s| s.at.unix_secs() < from);
        let hi = self.signals.partition_point(|s| s.at.unix_secs() <= to);
        &self.signals[lo..hi.max(lo)]
    }

    /// The strongest distinct activities around `at` that pass `keep`.
    pub fn support(&self, at: Timestamp, spec: &RuleSpec, keep: impl Fn(&Signal) -> bool) -> Support<'_> {
        let mut best: HashMap<(SignalClass, Option<&str>), (&Signal, f32)> = HashMap::new();
        for s in self.near(at, spec.max_days).iter().filter(|s| keep(s)) {
            let c = signal_weight(s.class) * decay(spec, days_between(s.at, at));
            let slot = best.entry((s.class, s.service.map(|x| x.id))).or_insert((s, c));
            if c > slot.1 {
                *slot = (s, c);
            }
        }
        let mut signals: Vec<(&Signal, f32)> = best.into_values().filter(|(_, c)| *c > 0.0).collect();
        signals.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.at.cmp(&b.0.at)));
        signals.truncate(3);
        let total = 1.0 - signals.iter().fold(1.0, |acc, (_, c)| acc * (1.0 - c.clamp(0.0, 1.0)));
        Support { signals, total }
    }
}

/// Per fund-holding service: first and last visit or account trace.
fn service_windows(signals: &[Signal], inputs: &LeadInputs) -> Vec<ServiceWindow> {
    let mut by_id: HashMap<&'static str, ServiceWindow> = HashMap::new();
    let mut add = |service: Service, at: Timestamp, event: Option<i64>, evidence: EvidenceId| {
        let w = by_id.entry(service.id).or_insert_with(|| ServiceWindow { service, first: at, last: at, traces: 0, events: Vec::new(), evidence: Vec::new() });
        w.first = w.first.min(at);
        w.last = w.last.max(at);
        w.traces += 1;
        if let Some(e) = event.filter(|_| w.events.len() < 50) {
            w.events.push(e);
        }
        if !w.evidence.contains(&evidence) {
            w.evidence.push(evidence);
        }
    };
    for s in signals {
        if let Some(service) = s.service.filter(|x| x.kind.holds_funds() && x.kind != ServiceKind::Payment) {
            add(service, s.at, Some(s.event_id), s.evidence);
        }
    }
    for a in &inputs.accounts {
        let (Some(service), Some((first, last))) = (a.service_id().and_then(Service::by_id), a.window()) else { continue };
        if service.kind.holds_funds() && service.kind != ServiceKind::Payment {
            for (at, ev) in [(first, a.disks().first()), (last, a.disks().last())] {
                add(service, at, None, ev.copied().unwrap_or(EvidenceId::new(0)));
            }
        }
    }
    let mut out: Vec<ServiceWindow> = by_id.into_values().collect();
    out.sort_by(|a, b| a.first.cmp(&b.first).then(a.service.id.cmp(b.service.id)));
    out
}
