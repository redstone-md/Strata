//! Ranking: how close each node is to money and to the owner. Base scores come from what a node
//! is (a funded address, a seed, an exchange account); identities earn theirs from ownership
//! signals; one propagation round then lifts whatever sits next to something valuable.

use crate::edge::{Edge, EdgeKind};
use crate::node::{ChainState, Node, NodeKind};
use strata_accounts::ServiceKind;
use strata_kernel::scan::HitCategory;

/// Share of the best neighbour's score a node gains.
const PROPAGATION: f32 = 0.25;
/// A satoshi balance this large scores the maximum.
const RICH_SAT: f64 = 100_000_000.0;

pub(crate) fn secret(category: HitCategory, confidence: f32) -> f32 {
    let base = match category {
        HitCategory::Mnemonic => 74.0,
        HitCategory::Wallet | HitCategory::ExtendedKey => 70.0,
        _ => 64.0,
    };
    base * (0.5 + 0.5 * confidence.clamp(0.0, 1.0))
}

/// Funded beats used beats merely found; more coins rank higher on a log scale.
pub(crate) fn address(chain: Option<ChainState>) -> f32 {
    match chain {
        Some(c) if c.balance_sat() > 0 => 88.0 + 12.0 * ((c.balance_sat() as f64).ln() / RICH_SAT.ln()).clamp(0.0, 1.0) as f32,
        Some(c) if c.used() => 58.0 + (c.tx_count.min(50) as f32) * 0.2,
        Some(_) => 6.0,
        None => 14.0,
    }
}

pub(crate) fn account(kind: Option<ServiceKind>, confidence: f32) -> f32 {
    let base = match kind {
        Some(k) if k.holds_funds() => 48.0,
        Some(k) if k.is_crypto() => 34.0,
        Some(_) => 16.0,
        None => 12.0,
    };
    base * (0.5 + 0.5 * confidence.clamp(0.0, 1.0))
}

/// What the case says about an identity belonging to the machine's user.
#[derive(Debug, Clone, Default)]
pub(crate) struct Ownership {
    /// Detail of the strongest artefact that names it (`saved browser login`).
    pub artefact: Option<String>,
    pub in_profile: bool,
    pub in_browser: bool,
    pub in_mail_client: bool,
    /// Equals a user profile folder name.
    pub profile_name: bool,
    /// Messages received / sent in live mailboxes.
    pub live_received: u64,
    pub live_sent: u64,
    /// The address most live mail on a disk was sent to.
    pub mailbox_owner: bool,
    /// File where it was found next to a key or wallet.
    pub next_to_secret: Option<String>,
    /// Only seen in system and software files.
    pub system_only: bool,
}

impl Ownership {
    /// Any sign at all that the identity is the user's own.
    pub fn any(&self) -> bool {
        self.artefact.is_some()
            || self.in_profile
            || self.profile_name
            || self.live_received > 0
            || self.live_sent > 0
            || self.next_to_secret.is_some()
    }

    /// Base score plus the sentences explaining it.
    pub fn score(&self) -> (f32, Vec<String>) {
        let mut score = 10.0;
        let mut why = Vec::new();
        let mut add = |points: f32, reason: String| {
            score += points;
            why.push(reason);
        };
        if let Some(a) = &self.artefact {
            add(22.0, format!("named by an artefact: {a}"));
        }
        if self.profile_name {
            add(14.0, "same name as a user profile folder".into());
        }
        if self.mailbox_owner {
            add(22.0, "most live mail on the disk was sent to it".into());
        } else if self.live_received > 0 {
            add(10.0, format!("received {} in a live mailbox", plural(self.live_received, "message")));
        }
        if self.live_sent > 0 {
            add(8.0, format!("sent {} from a live mailbox", plural(self.live_sent, "message")));
        }
        if let Some(f) = &self.next_to_secret {
            add(18.0, format!("found next to a key or wallet in {f}"));
        }
        if self.in_browser {
            add(8.0, "in browser data".into());
        } else if self.in_mail_client {
            add(8.0, "in a mail client's files".into());
        } else if self.in_profile {
            add(5.0, "in a user profile".into());
        }
        if self.system_only {
            score *= 0.4;
            why.push("only seen in system and software files".into());
        }
        (score.min(92.0), why)
    }
}

pub(crate) fn plural(n: u64, word: &str) -> String {
    if n == 1 { format!("1 {word}") } else { format!("{n} {word}s") }
}

/// Adjust identity scores by the accounts they hold, then lift every node by its best
/// neighbour (hubs neither give nor take). Runs once; the result does not depend on node order.
pub(crate) fn propagate(nodes: &mut [Node], edges: &[Edge], adjacency: &[Vec<usize>]) {
    for (i, list) in adjacency.iter().enumerate() {
        if nodes[i].kind != NodeKind::Identity {
            continue;
        }
        let funds = list.iter().filter(|e| edges[**e].kind == EdgeKind::HasAccount && nodes[edges[**e].other(i)].score >= 30.0).count();
        if funds > 0 {
            nodes[i].score = (nodes[i].score + 6.0 * funds.min(5) as f32).min(95.0);
            nodes[i].because(format!("{} on services that hold funds or deal in coins", plural(funds as u64, "account")));
        }
    }
    let base: Vec<f32> = nodes.iter().map(|n| n.score).collect();
    for (i, list) in adjacency.iter().enumerate() {
        if nodes[i].kind.is_hub() {
            continue;
        }
        let best = list
            .iter()
            .map(|e| (edges[*e].other(i), edges[*e].kind.strength()))
            .filter(|(j, _)| !nodes[*j].kind.is_hub())
            .map(|(j, s)| base[j] * s)
            .fold(0.0f32, f32::max);
        if best > base[i] {
            nodes[i].score = (base[i] + PROPAGATION * best).min(100.0);
        }
    }
    for (i, list) in adjacency.iter().enumerate() {
        if nodes[i].kind.is_hub() {
            let best = list.iter().map(|e| nodes[edges[*e].other(i)].score).fold(0.0f32, f32::max);
            nodes[i].score = nodes[i].score.max(best * 0.6);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_outranks_secrets_outranks_accounts() {
        let funded = address(Some(ChainState { funded_sat: 5_000_000, spent_sat: 0, tx_count: 1 }));
        let used = address(Some(ChainState { funded_sat: 1, spent_sat: 1, tx_count: 2 }));
        let empty = address(Some(ChainState::default()));
        assert!(funded > used && used > address(None) && address(None) > empty);
        assert!(secret(HitCategory::Mnemonic, 0.9) > account(Some(ServiceKind::Exchange), 0.9));
        assert!(account(Some(ServiceKind::Exchange), 0.9) > account(Some(ServiceKind::Forum), 0.9));
    }

    #[test]
    fn ownership_signals_add_up_and_system_files_pull_down() {
        let strong = Ownership { artefact: Some("saved browser login".into()), mailbox_owner: true, in_browser: true, ..Default::default() };
        let weak = Ownership { system_only: true, ..Default::default() };
        let (s, why) = strong.score();
        assert!(s > 50.0 && why.len() == 3);
        assert!(weak.score().0 < 10.0 && !weak.any());
    }
}
