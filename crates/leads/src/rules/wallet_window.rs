//! "wallet.dat (deleted) modified 2012-03-02, during the period the user was active on
//! Mt. Gox as login Z."

use super::{evidence_of, found_in};
use crate::engine::{Context, ServiceWindow};
use crate::fmt::{day, span};
use crate::inputs::KeyFinding;
use crate::lead::{Lead, LeadRef, LeadRule};
use crate::scoring::{BONUS_DELETED_FILE, account_weight, clamp_score, days_between, decay, finding_weight, rule};
use strata_accounts::Account;
use strata_kernel::Timestamp;

/// Days between a file time and a service window (0 inside it).
fn distance(at: Timestamp, w: &ServiceWindow) -> f32 {
    if w.first <= at && at <= w.last { 0.0 } else { days_between(at, w.first).min(days_between(at, w.last)) }
}

pub(crate) fn run(ctx: &Context<'_>) -> Vec<Lead> {
    let spec = rule(LeadRule::WalletFileInWindow);
    let mut out = Vec::new();
    for key in ctx.inputs.keys.iter().filter(|k| k.is_secret() && k.file_path.is_some()) {
        let times = [(key.file_modified, "last modified"), (key.file_created, "created")];
        let mut matches: Vec<(f32, Timestamp, &str, &ServiceWindow)> = Vec::new();
        for (at, what) in times.iter().filter_map(|(t, w)| Some((t.as_ref().copied()?, *w))) {
            for w in &ctx.windows {
                let strength = decay(spec, distance(at, w)) * account_weight(Some(w.service.kind));
                if strength > 0.0 {
                    matches.push((strength, at, what, w));
                }
            }
        }
        matches.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.3.service.id.cmp(b.3.service.id)));
        let mut seen = Vec::new();
        matches.retain(|m| !seen.contains(&m.3.service.id) && {
            seen.push(m.3.service.id);
            true
        });
        let Some(&(strength, at, what, w)) = matches.first() else { continue };
        out.push(lead(ctx, key, strength, at, what, w, &matches[1..matches.len().min(3)]));
    }
    out
}

fn accounts_on<'a>(ctx: &'a Context<'_>, w: &ServiceWindow) -> Vec<&'a Account> {
    ctx.inputs.accounts.iter().filter(|a| a.service_id() == Some(w.service.id)).take(3).collect()
}

fn lead(ctx: &Context<'_>, key: &KeyFinding, strength: f32, at: Timestamp, what: &str, w: &ServiceWindow, others: &[(f32, Timestamp, &str, &ServiceWindow)]) -> Lead {
    let spec = rule(LeadRule::WalletFileInWindow);
    let accounts = accounts_on(ctx, w);
    let logins = accounts.iter().map(|a| a.identifier()).collect::<Vec<_>>().join(", ");
    let as_login = if logins.is_empty() { String::new() } else { format!(" as {logins}") };
    let inside = distance(at, w) == 0.0;
    let relation = if inside { "while" } else { "close to when" };
    let mut explanation = vec![
        found_in(key),
        format!("The file was {what} on {}.", day(at)),
        format!(
            "The user was active on the {} {}{as_login} from {} ({} traces).",
            w.service.kind.label(),
            w.service.name,
            span(w.first, w.last),
            w.traces
        ),
    ];
    for (_, _, _, o) in others {
        explanation.push(format!("Also active then: the {} {} ({}).", o.service.kind.label(), o.service.name, span(o.first, o.last)));
    }
    explanation.push(format!(
        "Coins may have moved between this wallet and {}: compare its deposit and withdrawal history with the wallet's addresses.",
        w.service.name
    ));
    let mut refs = vec![LeadRef::Hit(key.hit_id)];
    refs.extend(accounts.iter().map(|a| LeadRef::Account(a.key().to_string())));
    refs.extend(w.events.iter().take(10).map(|e| LeadRef::Event(*e)));
    let score = spec.base * finding_weight(key.category) * strength + if key.deleted { BONUS_DELETED_FILE } else { 0.0 };
    Lead {
        id: format!("wallet:{}", key.hit_id),
        rule: LeadRule::WalletFileInWindow,
        title: format!("{} {what} {} {relation} {} was in use{as_login}", key.file_name(), day(at), w.service.name),
        explanation,
        score: clamp_score(score),
        refs,
        window: Some((w.first.min(at), w.last.max(at))),
        evidence: evidence_of(std::iter::once(key.evidence).chain(w.evidence.iter().copied()).filter(|e| e.get() > 0)),
    }
}
