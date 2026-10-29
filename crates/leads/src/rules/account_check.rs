//! "Account A on exchange B active 2013 — check this account for withdrawals to addresses
//! found on disk."

use super::evidence_of;
use crate::engine::Context;
use crate::fmt::{day, short_address, span};
use crate::lead::{Lead, LeadRef, LeadRule};
use crate::scoring::{BONUS_CHAIN_OVERLAP, account_weight, clamp_score, rule};
use strata_accounts::{AccountSource, Service, SourceRef};
use strata_kernel::Timestamp;

/// On-chain moves this close to an account's window count as overlapping it.
const OVERLAP_MARGIN_SECS: i64 = 30 * 86_400;

pub(crate) fn run(ctx: &Context<'_>) -> Vec<Lead> {
    let spec = rule(LeadRule::AccountCheck);
    let mut out = Vec::new();
    for a in ctx.inputs.accounts.iter().filter(|a| a.holds_funds()) {
        let weight = account_weight(a.service_kind());
        if weight <= 0.0 {
            continue;
        }
        let overlap = a.window().map(|w| chain_overlap(ctx, w)).unwrap_or_default();
        let mut score = spec.base * weight * a.confidence().max(0.3);
        if !overlap.is_empty() {
            score += BONUS_CHAIN_OVERLAP;
        }
        let entry = a.service_id().and_then(Service::by_id).map(Service::entry);
        let kind = a.service_kind().map_or("service", |k| k.label());
        let seen = match a.window() {
            Some((f, l)) => format!("seen {}", if f == l { format!("on {}", day(f)) } else { format!("from {}", span(f, l)) }),
            None => "seen without a date".to_string(),
        };
        let mut explanation = vec![format!(
            "Account {} ({}) on the {kind} {} was {seen} in {} on {}.",
            a.identifier(),
            a.kind().label(),
            a.service(),
            plural(a.sources().len(), "trace", "traces"),
            plural(a.disks().len(), "disk", "disks"),
        )];
        explanation.push(format!("Found as: {}.", describe_sources(a.sources())));
        if overlap.is_empty() {
            explanation.push("Check it for a remaining balance and for withdrawals to addresses found on the disks.".into());
        } else {
            let moves = overlap.iter().take(3).map(|(addr, t)| format!("{} on {}", short_address(addr), day(*t))).collect::<Vec<_>>().join(", ");
            explanation.push(format!("Found addresses moved coins while it was in use: {moves}."));
            explanation.push("Check the account for withdrawals to these addresses or a remaining balance.".into());
        }
        if let Some(e) = entry {
            if let Some(y) = e.years() {
                explanation.push(format!("{} operated {y}.", e.name()));
            }
            if !e.notes().is_empty() {
                explanation.push(format!("{}.", e.notes().trim_end_matches('.')));
            }
        }
        let linked: Vec<&str> = a.linked().iter().filter_map(|k| k.split_once('|').map(|(s, _)| s)).collect();
        if !linked.is_empty() {
            explanation.push(format!("The same name appears on: {}.", linked.join(", ")));
        }
        let mut refs = vec![LeadRef::Account(a.key().to_string())];
        refs.extend(a.sources().iter().take(10).filter_map(|s| match s.origin {
            SourceRef::Hit(id) => Some(LeadRef::Hit(id)),
            SourceRef::Event(id) => Some(LeadRef::Event(id)),
            SourceRef::File(_) => None,
        }));
        refs.extend(overlap.iter().take(5).map(|(addr, _)| LeadRef::Address(addr.clone())));
        out.push(Lead {
            id: format!("account:{}", a.key()),
            rule: LeadRule::AccountCheck,
            title: format!("Check {} account {}", a.service(), a.identifier()),
            explanation,
            score: clamp_score(score),
            refs,
            window: a.window(),
            evidence: evidence_of(a.disks().iter().copied()),
        });
    }
    out
}

/// `(address, time)` of found addresses' transactions within the window (± margin).
fn chain_overlap(ctx: &Context<'_>, (first, last): (Timestamp, Timestamp)) -> Vec<(String, Timestamp)> {
    let (from, to) = (first.unix_secs() - OVERLAP_MARGIN_SECS, last.unix_secs() + OVERLAP_MARGIN_SECS);
    let mut out: Vec<(String, Timestamp)> = Vec::new();
    for h in ctx.inputs.histories.iter().filter(|h| ctx.keys_by_address.contains_key(h.address.as_str())) {
        if let Some(t) = h.txs.iter().filter_map(|t| t.time).filter(|t| (from..=to).contains(&t.unix_secs())).min() {
            out.push((h.address.clone(), t));
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    out
}

fn describe_sources(sources: &[AccountSource]) -> String {
    let mut kinds: Vec<&str> = sources.iter().map(|s| s.detail.as_str()).filter(|d| !d.is_empty()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.is_empty() {
        return "byte-level traces".into();
    }
    let more = kinds.len().saturating_sub(4);
    let list = kinds.into_iter().take(4).collect::<Vec<_>>().join("; ");
    if more > 0 { format!("{list} and {more} more") } else { list }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}
