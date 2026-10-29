//! "Seed phrase found in a text file created 2014-01-10; Electrum installed 2014-01-09."

use super::{evidence_of, found_in};
use crate::engine::Context;
use crate::fmt::{day, relative, sentence};
use crate::lead::{Lead, LeadRef, LeadRule};
use crate::scoring::{BONUS_DELETED_FILE, clamp_score, days_between, decay, finding_weight, rule, signal_weight};
use crate::signal::SignalClass;

/// A secret written down this long after the software appeared still counts (same session).
const AFTER_GRACE_SECS: i64 = 86_400;

pub(crate) fn run(ctx: &Context<'_>) -> Vec<Lead> {
    let spec = rule(LeadRule::SecretAfterInstall);
    let mut out = Vec::new();
    for key in ctx.inputs.keys.iter().filter(|k| k.is_secret()) {
        let Some(created) = key.file_created else { continue };
        // Wallet software that arrived (or first ran) before the file was created.
        let best = ctx
            .near(created, spec.max_days)
            .iter()
            .filter(|s| matches!(s.class, SignalClass::WalletInstall | SignalClass::WalletRun))
            .filter(|s| s.at.unix_secs() <= created.unix_secs() + AFTER_GRACE_SECS)
            .map(|s| (s, signal_weight(s.class) * decay(spec, days_between(s.at, created))))
            .filter(|(_, c)| *c > 0.0)
            .max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.at.cmp(&a.0.at)));
        let Some((signal, strength)) = best else { continue };
        let software = signal.service.map(|s| s.name).unwrap_or("wallet software");
        let mut score = spec.base * finding_weight(key.category) * strength;
        if key.deleted {
            score += BONUS_DELETED_FILE;
        }
        let what = if signal.class == SignalClass::WalletInstall { "arrived" } else { "first ran" };
        out.push(Lead {
            id: format!("install:{}", key.hit_id),
            rule: LeadRule::SecretAfterInstall,
            title: format!("{} in {} created {}, after {software} {what}", sentence(key.noun()), key.file_name(), day(created)),
            explanation: vec![
                found_in(key),
                format!("The file was created on {}.", day(created)),
                sentence(format!("{} ({}) the user {}.", relative(signal.at, created), day(signal.at), signal.describe())),
                format!("A {} written right after {software} appeared is likely its backup: restore it in {software} first.", key.noun()),
            ],
            score: clamp_score(score),
            refs: vec![LeadRef::Hit(key.hit_id), LeadRef::Event(signal.event_id)],
            window: Some((signal.at.min(created), signal.at.max(created))),
            evidence: evidence_of([key.evidence, signal.evidence]),
        });
    }
    out
}
