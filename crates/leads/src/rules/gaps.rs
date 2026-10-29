//! "Crypto activity in spring 2013 but no wallet from that time": where to keep looking.

use super::evidence_of;
use crate::engine::Context;
use crate::fmt::span;
use crate::lead::{Lead, LeadRef, LeadRule};
use crate::scoring::{clamp_score, rule, signal_weight};
use crate::signal::{Signal, SignalClass};
use std::collections::BTreeMap;
use strata_kernel::Timestamp;

/// Signals this far apart start a new period.
const GAP_DAYS: i64 = 14;
/// Fewer signals than this do not make a period worth a lead.
const MIN_SIGNALS: usize = 5;
/// This many signals give the full base score.
const FULL_SIGNALS: f32 = 20.0;
/// Only signals at least this strong form periods (no bare forum reading).
const MIN_WEIGHT: f32 = 0.5;

pub(crate) fn run(ctx: &Context<'_>) -> Vec<Lead> {
    let spec = rule(LeadRule::ActivityWithoutWallet);
    let margin = spec.max_days * 86_400;
    let strong: Vec<&Signal> = ctx.signals.iter().filter(|s| signal_weight(s.class) >= MIN_WEIGHT).collect();
    let mut out = Vec::new();
    for period in periods(&strong) {
        let (first, last) = (period[0].at, period[period.len() - 1].at);
        let (from, to) = (first.unix_secs() - margin, last.unix_secs() + margin);
        let covered = |t: Option<Timestamp>| t.is_some_and(|t| (from..=to).contains(&t.unix_secs()));
        let key_then = ctx.inputs.keys.iter().any(|k| k.is_secret() && (covered(k.file_created) || covered(k.file_modified)));
        let chain_then = ctx.inputs.histories.iter().any(|h| h.txs.iter().any(|t| covered(t.time)));
        if key_then || chain_then || period.len() < MIN_SIGNALS {
            continue;
        }
        let score = spec.base * (period.len() as f32 / FULL_SIGNALS).min(1.0);
        out.push(Lead {
            id: format!("gap:{}", first.unix_secs().div_euclid(86_400)),
            rule: LeadRule::ActivityWithoutWallet,
            title: format!("Crypto activity {} with no wallet from that time", span(first, last)),
            explanation: vec![
                format!("{} crypto traces, {}: {}.", period.len(), span(first, last), summary(&period)),
                "No wallet, key or seed file and no on-chain activity of a found address dates from this period.".into(),
                "Look for deleted or carved wallets of that time, backups on other disks, and the accounts used then.".into(),
            ],
            score: clamp_score(score),
            refs: period.iter().take(20).map(|s| LeadRef::Event(s.event_id)).collect(),
            window: Some((first, last)),
            evidence: evidence_of(period.iter().map(|s| s.evidence)),
        });
    }
    out
}

/// Runs of signals with no gap longer than [`GAP_DAYS`].
fn periods<'a>(signals: &[&'a Signal]) -> Vec<Vec<&'a Signal>> {
    let mut out: Vec<Vec<&Signal>> = Vec::new();
    for s in signals {
        match out.last_mut() {
            Some(p) if p.last().is_some_and(|l| s.at.unix_secs() - l.at.unix_secs() <= GAP_DAYS * 86_400) => p.push(s),
            _ => out.push(vec![s]),
        }
    }
    out
}

/// `12 faucet visits, 3 wallet runs` — the most frequent kinds first.
fn summary(period: &[&Signal]) -> String {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for s in period {
        *counts.entry(noun(s.class)).or_default() += 1;
    }
    let mut v: Vec<(&str, usize)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.into_iter().take(4).map(|(n, c)| format!("{c} {n}")).collect::<Vec<_>>().join(", ")
}

fn noun(class: SignalClass) -> &'static str {
    match class {
        SignalClass::Faucet => "faucet visits",
        SignalClass::Exchange => "exchange visits",
        SignalClass::WebWallet => "web wallet visits",
        SignalClass::MiningPool => "pool visits",
        SignalClass::Gambling => "dice site visits",
        SignalClass::OtherCryptoSite => "other crypto site visits",
        SignalClass::Payment => "e-money uses",
        SignalClass::WalletRun => "wallet runs",
        SignalClass::WalletInstall => "wallet downloads",
        SignalClass::MiningRun => "miner runs",
        SignalClass::AccountUse => "account traces",
        SignalClass::MoneyMail => "money mails",
        SignalClass::WalletFile => "wallet file traces",
        SignalClass::Search => "crypto searches",
        SignalClass::Other => "other traces",
    }
}
