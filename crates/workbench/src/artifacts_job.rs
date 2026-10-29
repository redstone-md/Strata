//! Parse browser, registry and Windows artefacts of every filesystem into the case timeline,
//! identities and host facts.

use strata_artifacts::{ArtifactExtractor, IdentityKind, ProfileHints, fs_events};
use strata_case::{Attribution, Case, FileRef, HostFact};
use strata_fs::EntryState;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{Confidence, EvidenceId, Result};

/// Filesystem MACB events kept per volume; beyond this the timeline gets unusable anyway.
const MAX_FS_EVENTS: usize = 2_000_000;

pub struct ArtifactsJob<'a> {
    case: &'a Case,
}

impl<'a> ArtifactsJob<'a> {
    pub fn new(case: &'a Case) -> Self {
        Self { case }
    }

    /// Returns `(events, identities, facts)`.
    pub fn run(&self, id: EvidenceId) -> Result<(usize, usize, usize)> {
        let layout = self.case.layout(id)?;
        self.case.clear_events(id)?;
        let extractor = ArtifactExtractor::new(ProfileHints::default());
        let (mut events, mut identities, mut facts) = (0, 0, 0);
        for (vol, fs) in layout.filesystems() {
            let results = extractor.extract(fs);
            events += self.case.store_events(id, &results.events)?;
            let fs_timeline: Vec<_> = fs_events(fs).take(MAX_FS_EVENTS).collect();
            events += self.case.store_events(id, &fs_timeline)?;

            let hits: Vec<(Hit, Attribution)> = results
                .identities
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
                    (hit, Attribution { volume: Some(vol.index), file: Some(file) })
                })
                .collect();
            identities += self.case.store_hits(id, &hits)?;

            let host: Vec<HostFact> = results
                .facts
                .iter()
                .map(|f| HostFact {
                    evidence: id,
                    key: f.key.clone(),
                    value: f.value.clone(),
                    artifact: f.artifact.clone(),
                    source: f.source.clone(),
                })
                .collect();
            facts += host.len();
            self.case.store_facts(&host)?;
        }
        Ok((events, identities, facts))
    }
}
