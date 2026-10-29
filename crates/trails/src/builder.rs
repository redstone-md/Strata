//! Builds every trail of a case: reads traces out of the events, turns files, findings,
//! archive members and attachments into sightings, groups them into files and judges each.

use crate::cluster::{Seen, Sighting, clusters};
use crate::fate::Judged;
use crate::hints::{Hints, is_context};
use crate::inputs::{TrailInputs, WalletHit};
use crate::path_key::PathKey;
use crate::steps::{order, software_steps, steps};
use crate::traces::{Traces, wallet_named};
use crate::trail::{Fate, Trail};
use std::collections::HashSet;
use strata_crypto::{WalletFileName, WalletNameKind};
use strata_kernel::EvidenceId;

/// Trails are built from at most this many sightings per group in their steps.
const MAX_STEPS: usize = 60;

/// Reconstructs where wallet-relevant files went. Pure: the same inputs give the same trails.
pub struct TrailBuilder {
    max_trails: usize,
}

impl Default for TrailBuilder {
    fn default() -> Self {
        Self { max_trails: 5_000 }
    }
}

impl TrailBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every trail, best score first.
    pub fn build(&self, inputs: &TrailInputs) -> Vec<Trail> {
        // A file that holds a finding counts whatever its name.
        let secret_files: HashSet<String> = inputs.hits.iter().filter_map(|h| h.file_path.as_deref()).map(|p| PathKey::of(p).as_str().to_string()).collect();
        let traces = Traces::read(&inputs.events, |p, k| wallet_named(p) || secret_files.contains(k.as_str()));
        let mut sightings: Vec<Sighting<'_>> = traces.references.iter().cloned().map(Sighting::reference).collect();
        sightings.extend(inputs.files.iter().map(Sighting::file));
        sightings.extend(inputs.hits.iter().map(Sighting::hit));
        sightings.extend(inputs.members.iter().map(Sighting::member).filter(|s| wallet_named(s.key.name())));
        sightings.extend(inputs.attachments.iter().filter(|a| wallet_named(&a.name)).map(Sighting::attachment));

        let groups = clusters(&sightings);
        let standing: Vec<Vec<&Sighting<'_>>> =
            groups.iter().map(|g| g.iter().map(|&i| &sightings[i]).collect::<Vec<_>>()).filter(|g: &Vec<&Sighting<'_>>| stands(g)).collect();
        let claimed: HashSet<i64> = standing.iter().flatten().filter_map(|s| if let Seen::Hit(h) = s.seen { Some(h.id) } else { None }).collect();
        let pool: Vec<&WalletHit> = inputs.hits.iter().filter(|h| h.is_free() && !claimed.contains(&h.id)).collect();
        let hints = Hints::new(&pool);

        let mut trails: Vec<Trail> = standing.iter().map(|g| self.trail(g, &traces, &hints)).collect();
        trails.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
        trails.truncate(self.max_trails);
        trails
    }

    fn trail(&self, group: &[&Sighting<'_>], traces: &Traces<'_>, hints: &Hints<'_>) -> Trail {
        let judged = Judged::judge(group);
        let kind = WalletFileName::classify(&judged.origin_written)
            .or_else(|| group.iter().find_map(|s| WalletFileName::classify(&s.name())));
        let mut disks: Vec<EvidenceId> = group.iter().map(|s| s.evidence()).collect();
        disks.sort();
        disks.dedup();
        let mut chain = steps(group);
        chain.truncate(MAX_STEPS);
        let first = chain.iter().filter_map(|s| s.at).min();
        chain.extend(software_steps(&traces.software, kind, &disks, first));
        order(&mut chain);
        let hints = hints.for_trail(judged.verdict.fate, kind, group, &chain, &disks);
        let dated: Vec<_> = chain.iter().filter(|s| !is_context(s.kind)).filter_map(|s| s.at).collect();
        let dated = if dated.is_empty() { chain.iter().filter_map(|s| s.at).collect() } else { dated };
        let window = dated.iter().min().zip(dated.iter().max()).map(|(a, b)| (*a, *b));
        let references = group.iter().filter(|s| matches!(s.seen, Seen::Reference(_))).count();
        let score = score(judged.verdict.fate, judged.verdict.confidence, references, kind);
        let id = if judged.origin.as_str().starts_with('@') { format!("hit{}", judged.origin.as_str()) } else { judged.origin.as_str().to_string() };
        Trail {
            id,
            name: group.iter().find(|s| s.key == judged.origin).map_or_else(|| judged.origin.name().to_string(), |s| display_name(s)),
            kind,
            origin: judged.origin_written,
            verdict: judged.verdict,
            steps: chain,
            hints,
            score,
            window,
            evidence: disks,
        }
    }
}

/// The name as written (keeps its case), for titles.
fn display_name(s: &Sighting<'_>) -> String {
    let written = match &s.seen {
        Seen::Reference(r) => r.written.as_str(),
        Seen::File(f) => f.path.as_str(),
        Seen::Member(m) => m.member_path.as_str(),
        Seen::Attachment(a) => a.name.as_str(),
        Seen::Hit(h) => return h.file_path.as_deref().map_or_else(|| h.label.clone(), |p| p.rsplit(['/', '\\']).next().unwrap_or(p).to_string()),
    };
    written.rsplit(['/', '\\']).find(|n| !n.is_empty()).unwrap_or(written).to_string()
}

/// Is a group worth a trail? Traces, wallet-named or wallet-typed files and strong findings
/// are; a weak database header in free space only serves as a candidate for other trails.
fn stands(group: &[&Sighting<'_>]) -> bool {
    group.iter().any(|s| match &s.seen {
        Seen::Reference(_) | Seen::Member(_) | Seen::Attachment(_) => true,
        Seen::File(f) => wallet_named(&f.path) || f.detected_type.as_deref().is_some_and(|t| t.to_lowercase().contains("wallet")),
        Seen::Hit(h) => h.stands_alone(),
    })
}

/// 0..=95: what following the trail may gain, how sure the verdict is, how many traces back
/// it, and whether it is a wallet program's file or a note.
fn score(fate: Fate, confidence: f32, references: usize, kind: Option<WalletNameKind>) -> f32 {
    let wallet = if kind.is_some_and(WalletNameKind::is_wallet_file) { 4.0 } else { 0.0 };
    (fate.weight() * (0.6 + 0.4 * confidence.clamp(0.0, 1.0)) + references.min(5) as f32 + wallet).clamp(0.0, 95.0)
}
