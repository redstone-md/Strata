//! "Key X's address received coins on 2011-06-14; that day the user visited faucet Y and ran
//! Bitcoin-Qt."

use super::{evidence_of, found_in, support_sentences};
use crate::engine::Context;
use crate::fmt::{btc, day, sentence, short_address, span};
use crate::inputs::KeyFinding;
use crate::lead::{Lead, LeadRef, LeadRule};
use crate::scoring::{BONUS_SECOND_SIGNAL, BONUS_UNSPENT, UNSUPPORTED_SHARE, clamp_score, finding_weight, rule};
use strata_kernel::Timestamp;

/// A dated movement of coins: `(time, satoshi, received?)`.
type Movement = (Timestamp, u64, bool);

pub(crate) fn run(ctx: &Context<'_>) -> Vec<Lead> {
    let spec = rule(LeadRule::OnChainActivity);
    let mut out = Vec::new();
    for h in &ctx.inputs.histories {
        let Some(keys) = ctx.keys_by_address.get(h.address.as_str()) else { continue };
        let Some(key) = keys.iter().copied().max_by(|a, b| finding_weight(a.category).total_cmp(&finding_weight(b.category)).then(b.hit_id.cmp(&a.hit_id))) else {
            continue;
        };
        let moves: Vec<Movement> = h.receipts().into_iter().map(|(t, s)| (t, s, true)).chain(h.spends().into_iter().map(|(t, s)| (t, s, false))).collect();
        // The movement with the strongest timeline support (earliest on ties).
        let Some((anchor, support)) = moves
            .iter()
            .map(|m| (*m, ctx.support(m.0, spec, |_| true)))
            .max_by(|a, b| a.1.total.total_cmp(&b.1.total).then(b.0.0.cmp(&a.0.0)))
        else {
            continue;
        };
        let (at, sat, received) = anchor;
        let unspent = h.complete.then(|| h.receipts().iter().map(|r| r.1).sum::<u64>().saturating_sub(h.spends().iter().map(|s| s.1).sum())).filter(|u| *u > 0);
        let mut score = spec.base * finding_weight(key.category) * (UNSUPPORTED_SHARE + (1.0 - UNSUPPORTED_SHARE) * support.total);
        score += unspent.map_or(0.0, |_| BONUS_UNSPENT) + if support.signals.len() > 1 { BONUS_SECOND_SIGNAL } else { 0.0 };

        let verb = if received { "received" } else { "sent" };
        let mut explanation = vec![found_in(key)];
        explanation.push(movement_sentence(key, &h.address, verb, sat, at, &moves));
        if support.signals.is_empty() {
            explanation.push(format!("No crypto activity is on the timeline within {} days of it.", spec.max_days));
        } else {
            explanation.extend(support_sentences(&support, at));
        }
        if let Some(u) = unspent {
            explanation.push(format!("By the fetched history the address still holds {}.", btc(u)));
        } else if !h.complete {
            explanation.push(format!("Only the newest {} of {} transactions were fetched.", h.txs.len(), h.tx_count));
        }
        explanation.push(next_step(received, key.is_secret(), !support.signals.is_empty()));

        let mut refs: Vec<LeadRef> = keys.iter().map(|k| LeadRef::Hit(k.hit_id)).collect();
        refs.push(LeadRef::Address(h.address.clone()));
        refs.extend(support.signals.iter().map(|(s, _)| LeadRef::Event(s.event_id)));
        let window = h.first_seen().zip(h.last_seen());
        out.push(Lead {
            id: format!("onchain:{}", h.address),
            rule: LeadRule::OnChainActivity,
            title: format!("{} {verb} {} on {}", short_address(&h.address), btc(sat), day(at)),
            explanation,
            score: clamp_score(score),
            refs,
            window,
            evidence: evidence_of(keys.iter().map(|k| k.evidence).chain(support.signals.iter().map(|(s, _)| s.evidence))),
        });
    }
    out
}

fn movement_sentence(key: &KeyFinding, address: &str, verb: &str, sat: u64, at: Timestamp, moves: &[Movement]) -> String {
    let whose = if key.category == strata_kernel::scan::HitCategory::Address { "The address".to_string() } else { format!("Its address {address}") };
    let mut s = format!("{whose} {verb} {} on {}", btc(sat), day(at));
    if moves.len() > 1 {
        let (first, last) = (moves.iter().map(|m| m.0).min(), moves.iter().map(|m| m.0).max());
        if let (Some(a), Some(b)) = (first, last) {
            s += &format!("; {} transactions in all, {}", moves.len(), span(a, b));
        }
    }
    s + "."
}

fn next_step(received: bool, secret: bool, supported: bool) -> String {
    let control = if secret { "the key that controls the address was found" } else { "only the address was found, not its key" };
    match (received, !supported) {
        (true, false) => format!("Check whether the coins came from that activity; {control}."),
        (true, true) => sentence(format!("{control}; look at that day in the timeline for where the coins came from.")),
        (false, _) => "The coins were moved on; follow the transaction to see where they went (an exchange deposit or another wallet).".to_string(),
    }
}
