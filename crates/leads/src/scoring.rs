//! Tunable scoring, as data: per-rule base scores and time windows, per-signal weights, per-
//! finding weights. Time proximity decays by half every `half_life_days` and stops counting
//! beyond `max_days`.

use crate::lead::LeadRule;
use crate::signal::SignalClass;
use strata_accounts::ServiceKind;
use strata_kernel::Timestamp;
use strata_kernel::scan::HitCategory;

pub struct RuleSpec {
    pub rule: LeadRule,
    /// Score of a perfect match, 0..=100.
    pub base: f32,
    pub half_life_days: f32,
    /// Farther than this, a signal does not count at all.
    pub max_days: i64,
}

pub const RULES: &[RuleSpec] = &[
    RuleSpec { rule: LeadRule::OnChainActivity, base: 80.0, half_life_days: 2.0, max_days: 14 },
    RuleSpec { rule: LeadRule::SecretAfterInstall, base: 70.0, half_life_days: 3.0, max_days: 30 },
    RuleSpec { rule: LeadRule::WalletFileInWindow, base: 60.0, half_life_days: 30.0, max_days: 120 },
    RuleSpec { rule: LeadRule::AccountCheck, base: 55.0, half_life_days: 30.0, max_days: 180 },
    RuleSpec { rule: LeadRule::ActivityWithoutWallet, base: 45.0, half_life_days: 30.0, max_days: 30 },
];

pub fn rule(rule: LeadRule) -> &'static RuleSpec {
    RULES.iter().find(|r| r.rule == rule).unwrap_or(&RULES[0])
}

/// How strongly an activity supports "coins moved / a wallet was made here".
pub const SIGNAL_WEIGHTS: &[(SignalClass, f32)] = &[
    (SignalClass::Faucet, 1.0),
    (SignalClass::Exchange, 1.0),
    (SignalClass::WebWallet, 1.0),
    (SignalClass::WalletRun, 1.0),
    (SignalClass::MoneyMail, 1.0),
    (SignalClass::WalletInstall, 0.9),
    (SignalClass::MiningPool, 0.9),
    (SignalClass::AccountUse, 0.9),
    (SignalClass::WalletFile, 0.8),
    (SignalClass::MiningRun, 0.8),
    (SignalClass::Gambling, 0.7),
    (SignalClass::Payment, 0.5),
    (SignalClass::Search, 0.5),
    (SignalClass::OtherCryptoSite, 0.4),
    (SignalClass::Other, 0.3),
];

pub fn signal_weight(class: SignalClass) -> f32 {
    SIGNAL_WEIGHTS.iter().find(|(c, _)| *c == class).map_or(0.3, |(_, w)| *w)
}

/// How much a finding is worth as the subject of a lead.
pub const FINDING_WEIGHTS: &[(HitCategory, f32)] = &[
    (HitCategory::Wallet, 1.0),
    (HitCategory::PrivateKey, 1.0),
    (HitCategory::Mnemonic, 1.0),
    (HitCategory::ExtendedKey, 1.0),
    (HitCategory::Address, 0.6),
];

pub fn finding_weight(category: HitCategory) -> f32 {
    FINDING_WEIGHTS.iter().find(|(c, _)| *c == category).map_or(0.4, |(_, w)| *w)
}

/// How likely an account on this kind of service still matters for recovery.
pub const ACCOUNT_WEIGHTS: &[(ServiceKind, f32)] = &[
    (ServiceKind::Exchange, 1.0),
    (ServiceKind::WebWallet, 1.0),
    (ServiceKind::MiningPool, 0.8),
    (ServiceKind::Faucet, 0.6),
    (ServiceKind::Lending, 0.6),
    (ServiceKind::Gambling, 0.6),
    (ServiceKind::Payment, 0.4),
];

pub fn account_weight(kind: Option<ServiceKind>) -> f32 {
    kind.and_then(|k| ACCOUNT_WEIGHTS.iter().find(|(c, _)| *c == k)).map_or(0.0, |(_, w)| *w)
}

/// Bonus points (added, then capped at 100).
pub const BONUS_UNSPENT: f32 = 15.0;
pub const BONUS_SECOND_SIGNAL: f32 = 5.0;
pub const BONUS_CHAIN_OVERLAP: f32 = 15.0;
pub const BONUS_DELETED_FILE: f32 = 5.0;
/// Share of the base a lead keeps when no supporting timeline signal exists.
pub const UNSUPPORTED_SHARE: f32 = 0.35;

pub fn days_between(a: Timestamp, b: Timestamp) -> f32 {
    (a.unix_secs() - b.unix_secs()).abs() as f32 / 86_400.0
}

/// `0.5^(days / half_life)`, or 0 beyond `max_days`.
pub fn decay(spec: &RuleSpec, days: f32) -> f32 {
    if days > spec.max_days as f32 { 0.0 } else { 0.5f32.powf(days / spec.half_life_days.max(0.01)) }
}

pub fn clamp_score(s: f32) -> f32 {
    s.clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_halves_and_cuts_off() {
        let spec = rule(LeadRule::OnChainActivity);
        assert!((decay(spec, 0.0) - 1.0).abs() < 1e-6);
        assert!((decay(spec, 2.0) - 0.5).abs() < 1e-6);
        assert_eq!(decay(spec, 15.0), 0.0);
        assert!(RULES.iter().all(|r| r.base > 0.0 && r.base <= 100.0));
        assert_eq!(signal_weight(SignalClass::Faucet), 1.0);
        assert_eq!(account_weight(Some(ServiceKind::Mail)), 0.0);
    }
}
