//! Parse browser, registry and Windows artefacts of every filesystem into the case timeline,
//! identities and host facts — one volume per commit. A fresh run clears the evidence's
//! stored events first; a resumed run keeps what finished volumes stored.

use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use strata_artifacts::{ArtifactExtractor, IdentityKind, IdentityRecord, ProfileHints, fs_events};
use strata_case::{Attribution, FileRef, HostFact};
use strata_fs::EntryState;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, Result};

/// Filesystem MACB events kept per volume; beyond this the timeline gets unusable anyway.
const MAX_FS_EVENTS: usize = 2_000_000;

#[derive(Debug, Default, Serialize, Deserialize)]
struct ArtifactsCursor {
    /// Volumes whose events, identities and facts are stored.
    volumes: Vec<u32>,
    events: usize,
    identities: usize,
    facts: usize,
}

impl Cursor for ArtifactsCursor {
    fn note(&self) -> String {
        if self.volumes.is_empty() {
            "the first volume".into()
        } else {
            format!("after volume {} ({} events stored)", super::list(&self.volumes), self.events)
        }
    }
}

fn identity_hits(volume: u32, identities: &[IdentityRecord]) -> Vec<(Hit, Attribution)> {
    identities
        .iter()
        .map(|r| {
            let hit = Hit::new("artifacts.identity", HitCategory::Identity, 0, 0)
                .label(match r.kind {
                    IdentityKind::Email => "e-mail (artefact)",
                    IdentityKind::Login => "login",
                    IdentityKind::Nickname => "nickname",
                    IdentityKind::Phone => "phone",
                    IdentityKind::UserId => "user id",
                })
                .value(r.value.to_lowercase())
                .confidence(if r.weak { Confidence::MEDIUM } else { Confidence::HIGH })
                .details(serde_json::to_value(r).unwrap_or_default());
            let file = FileRef { path: r.source.clone(), state: EntryState::Allocated, file_offset: 0 };
            (hit, Attribution { volume: Some(volume), file: Some(file) })
        })
        .collect()
}

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    let id = ctx.evidence();
    let layout = ctx.case().layout(id)?;
    let mut cur = match ctx.cursor::<ArtifactsCursor>() {
        Some(cur) => cur,
        None => {
            let fresh = ArtifactsCursor::default();
            ctx.commit(&fresh, |w| w.clear_events(id))?;
            fresh
        }
    };
    let volumes: Vec<_> = layout.filesystems().collect();
    ctx.control().begin_at(cur.volumes.len() as u64, volumes.len() as u64);
    let extractor = ArtifactExtractor::new(ProfileHints::default());
    for &(vol, fs) in &volumes {
        if cur.volumes.contains(&vol.index) {
            continue;
        }
        if ctx.should_stop() {
            return Ok(String::new());
        }
        ctx.current(&format!("volume {}", vol.index));
        let results = extractor.extract(fs);
        let fs_timeline: Vec<_> = fs_events(fs).take(MAX_FS_EVENTS).collect();
        let hits = identity_hits(vol.index, &results.identities);
        let facts: Vec<HostFact> = results
            .facts
            .iter()
            .map(|f| HostFact {
                evidence: id,
                volume: Some(vol.index),
                key: f.key.clone(),
                value: f.value.clone(),
                artifact: f.artifact.clone(),
                source: f.source.clone(),
            })
            .collect();
        if ctx.should_stop() {
            return Ok(String::new());
        }
        cur.volumes.push(vol.index);
        cur.events += results.events.len() + fs_timeline.len();
        cur.identities += hits.len();
        cur.facts += facts.len();
        ctx.commit(&cur, |w| {
            w.volume_events(id, vol.index, &results.events)?;
            w.volume_events(id, vol.index, &fs_timeline)?;
            w.facts(&facts)?;
            w.hits(id, &hits)
        })?;
        ctx.log(format!(
            "volume {}: {} artefact events, {} filesystem events, {} identities, {} host facts",
            vol.index,
            results.events.len(),
            fs_timeline.len(),
            hits.len(),
            facts.len()
        ));
        ctx.control().item_done();
    }
    Ok(format!("{} events, {} identities, {} host facts", cur.events, cur.identities, cur.facts))
}
