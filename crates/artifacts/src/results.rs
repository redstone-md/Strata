//! What artefact parsers produce: dated events, identities, host facts and damage.

use crate::tag::Tagger;
use serde::{Deserialize, Serialize};
use strata_kernel::{Confidence, Damage, Timestamp};
use strata_timeline::{EventKind, EventSource, TimelineEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IdentityKind {
    Email,
    Login,
    Nickname,
    Phone,
}

/// An account name / address seen in an artefact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub kind: IdentityKind,
    pub value: String,
    /// Service name (`Mail.ru`, `VKontakte`, site host, `Windows`).
    pub service: Option<String>,
    /// Evidence file path.
    pub source: String,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
}

impl IdentityRecord {
    fn same_as(&self, other: &IdentityRecord) -> bool {
        self.kind == other.kind && self.value.eq_ignore_ascii_case(&other.value) && self.service == other.service
    }

    fn widen(&mut self, other: &IdentityRecord) {
        self.first_seen = min_opt(self.first_seen, other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
    }
}

fn min_opt(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Timestamp> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    }
}

/// A non-dated fact about the host or an undated trace (`computer_name`, `url`, `machine_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub key: String,
    pub value: String,
    /// Parser id that produced the fact.
    pub artifact: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactResults {
    pub events: Vec<TimelineEvent>,
    pub identities: Vec<IdentityRecord>,
    pub facts: Vec<Fact>,
    pub damage: Vec<Damage>,
}

impl ArtifactResults {
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.identities.is_empty() && self.facts.is_empty()
    }

    /// Point everything at the evidence file it came from.
    pub fn attach(&mut self, path: &str, deleted: bool, actor: Option<&str>) {
        for e in &mut self.events {
            e.set_origin(path, deleted);
            if let Some(a) = actor
                && e.actor().is_none()
            {
                e.set_actor(a);
            }
        }
        for i in self.identities.iter_mut().filter(|i| i.source.is_empty()) {
            i.source = path.to_string();
        }
        for f in self.facts.iter_mut().filter(|f| f.source.is_empty()) {
            f.source = path.to_string();
        }
    }

    /// Append `other`, merging duplicate identities (widening their seen window).
    pub fn merge(&mut self, other: ArtifactResults) {
        self.events.extend(other.events);
        for id in other.identities {
            self.add_identity(id);
        }
        self.facts.extend(other.facts);
        self.damage.extend(other.damage);
    }

    pub fn add_identity(&mut self, id: IdentityRecord) {
        match self.identities.iter_mut().find(|x| x.same_as(&id)) {
            Some(existing) => existing.widen(&id),
            None => self.identities.push(id),
        }
    }

    /// Apply service / keyword tags to every event and fill missing identity services.
    pub fn tag(&mut self) {
        let tagger = Tagger::shared();
        for e in &mut self.events {
            tagger.tag_event(e);
        }
        for i in self.identities.iter_mut().filter(|i| i.service.is_none()) {
            i.service = tagger.service_name(&i.value);
        }
    }
}

/// Builds one parser's results; every event gets the parser id as its artifact.
pub(crate) struct Recorder {
    artifact: &'static str,
    out: ArtifactResults,
}

impl Recorder {
    pub fn new(artifact: &'static str) -> Self {
        Self { artifact, out: ArtifactResults::default() }
    }

    /// Event template; `None` when the time is missing or implausible.
    pub fn make(&self, at: Option<Timestamp>, kind: EventKind, title: impl Into<String>) -> Option<TimelineEvent> {
        Some(TimelineEvent::new(at?, kind, title, EventSource::new(self.artifact, "")))
    }

    /// Record a dated event; undated traces become `undated` facts so nothing is lost.
    pub fn emit(&mut self, at: Option<Timestamp>, kind: EventKind, title: impl Into<String>, detail: impl Into<String>) {
        let title = title.into();
        match self.make(at, kind, title.clone()) {
            Some(e) => self.out.events.push(e.with_detail(detail)),
            None if !title.is_empty() => self.fact("undated", title),
            None => {}
        }
    }

    /// Like [`Recorder::emit`] but silently drops undated events (optional timestamps).
    pub fn dated(&mut self, at: Option<Timestamp>, kind: EventKind, title: impl Into<String>, detail: impl Into<String>) {
        if let Some(e) = self.make(at, kind, title) {
            self.out.events.push(e.with_detail(detail));
        }
    }

    pub fn push(&mut self, event: TimelineEvent) {
        self.out.events.push(event);
    }

    /// Secondary or approximate event at low confidence (dropped when undated).
    pub fn push_low(&mut self, at: Option<Timestamp>, kind: EventKind, title: impl Into<String>, detail: impl Into<String>) {
        if let Some(e) = self.make(at, kind, title) {
            self.push(e.with_detail(detail).with_confidence(Confidence::LOW));
        }
    }

    pub fn identity(&mut self, kind: IdentityKind, value: &str, service: Option<&str>, at: Option<Timestamp>) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        self.out.add_identity(IdentityRecord {
            kind,
            value: value.to_string(),
            service: service.map(str::to_string),
            source: String::new(),
            first_seen: at,
            last_seen: at,
        });
    }

    pub fn fact(&mut self, key: &str, value: impl Into<String>) {
        let value = value.into();
        if !value.trim().is_empty() {
            self.out.facts.push(Fact { key: key.to_string(), value, artifact: self.artifact.to_string(), source: String::new() });
        }
    }

    pub fn damage(&mut self, damage: Damage) {
        self.out.damage.push(damage);
    }

    pub fn finish(self) -> ArtifactResults {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_merge_and_widen() {
        let t1 = Timestamp::from_unix_secs(1_300_000_000);
        let t2 = Timestamp::from_unix_secs(1_310_000_000);
        let mut r = Recorder::new("t");
        r.identity(IdentityKind::Email, "ivan.test2@mail.ru", None, t2);
        r.identity(IdentityKind::Email, "ivan.test2@mail.ru", None, t1);
        r.emit(None, EventKind::Other, "no time", "");
        let mut out = r.finish();
        out.tag();
        out.attach("/p", true, Some("Admin"));
        assert_eq!(out.identities.len(), 1);
        assert_eq!(out.identities[0].first_seen, t1);
        assert_eq!(out.identities[0].last_seen, t2);
        assert_eq!(out.identities[0].service.as_deref(), Some("Mail.ru"));
        assert_eq!(out.facts[0].key, "undated");
        assert_eq!(out.facts[0].source, "/p");
    }
}
