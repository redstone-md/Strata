//! Aggregated reads of the timeline and host facts for machine profiles: activity per hour and
//! file, events grouped by title, facts of chosen keys, and facts grouped by key for raw views.
//! The caller says which kinds and titles count; nothing here knows what "activity" means.

use crate::Case;
use crate::timeline::HostFact;
use rusqlite::ToSql;
use serde::Serialize;
use strata_kernel::{EvidenceId, Result, Timestamp};

/// Which events to read: kinds kept whatever their title, kinds kept only for some titles,
/// and title prefixes that are always left out.
#[derive(Debug, Clone, Default)]
pub struct EventFilter<'a> {
    pub kinds: &'a [&'a str],
    /// Kinds kept only when the title starts with one of `title_prefixes` or contains one of
    /// `title_infixes`.
    pub titled_kinds: &'a [&'a str],
    pub title_prefixes: &'a [&'a str],
    pub title_infixes: &'a [&'a str],
    /// Also keep events of `titled_kinds` tagged crypto-related.
    pub or_crypto: bool,
    pub excluded_prefixes: &'a [&'a str],
}

impl EventFilter<'_> {
    /// SQL condition and its arguments (numbered from `first`).
    fn clause(&self, first: usize) -> (String, Vec<String>) {
        let mut args: Vec<String> = Vec::new();
        let mut arg = |v: String| {
            args.push(v);
            format!("?{}", first + args.len() - 1)
        };
        let list = |items: &[&str], arg: &mut dyn FnMut(String) -> String| items.iter().map(|k| arg(k.to_string())).collect::<Vec<_>>().join(", ");
        let mut any = Vec::new();
        if !self.kinds.is_empty() {
            any.push(format!("kind IN ({})", list(self.kinds, &mut arg)));
        }
        if !self.titled_kinds.is_empty() {
            let kinds = list(self.titled_kinds, &mut arg);
            let mut titles: Vec<String> = self.title_prefixes.iter().map(|p| format!("title LIKE {}", arg(format!("{p}%")))).collect();
            titles.extend(self.title_infixes.iter().map(|p| format!("title LIKE {}", arg(format!("%{p}%")))));
            if self.or_crypto {
                titles.push("crypto = 1".into());
            }
            if !titles.is_empty() {
                any.push(format!("(kind IN ({kinds}) AND ({}))", titles.join(" OR ")));
            }
        }
        let mut sql = if any.is_empty() { "0".to_string() } else { format!("({})", any.join(" OR ")) };
        for p in self.excluded_prefixes {
            sql += &format!(" AND title NOT LIKE {}", arg(format!("{p}%")));
        }
        (sql, args)
    }
}

/// Events of one kind from one file in one hour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HourlyEvents {
    pub volume: Option<u32>,
    pub path: String,
    pub kind: String,
    /// Hours since the Unix epoch, UTC.
    pub hour: i64,
    pub count: u64,
}

/// Events of one kind and title from one file.
#[derive(Debug, Clone)]
pub struct TitledEvents {
    pub volume: Option<u32>,
    pub path: String,
    pub artifact: String,
    pub kind: String,
    pub title: String,
    pub first: Timestamp,
    pub last: Timestamp,
    pub count: u64,
    pub crypto: bool,
}

/// Distinct values of one fact key with how often each was stored.
#[derive(Debug, Clone, Serialize)]
pub struct FactGroup {
    pub key: String,
    /// Facts stored under the key.
    pub total: u64,
    /// Distinct values under the key.
    pub distinct: u64,
    /// The most frequent values (`value`, `count`, one source).
    pub values: Vec<(String, u64, String)>,
}

const HOUR_MICROS: i64 = 3_600_000_000;

impl Case {
    /// Events matching `filter`, counted per volume, file, kind and hour.
    pub fn hourly_events(&self, evidence: EvidenceId, filter: &EventFilter<'_>) -> Result<Vec<HourlyEvents>> {
        let (clause, args) = filter.clause(2);
        let sql = format!(
            "SELECT volume, path, kind, at / {HOUR_MICROS}, COUNT(*) FROM events WHERE evidence_id = ?1 AND {clause}
             GROUP BY volume, path, kind, at / {HOUR_MICROS}"
        );
        let bound = params(evidence, &args);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(bound.iter().map(|a| a.as_ref())), |r| {
                Ok(HourlyEvents { volume: r.get(0)?, path: r.get(1)?, kind: r.get(2)?, hour: r.get(3)?, count: r.get::<_, i64>(4)? as u64 })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// Events matching `filter`, grouped by volume, file, kind and title.
    pub fn titled_events(&self, evidence: EvidenceId, filter: &EventFilter<'_>) -> Result<Vec<TitledEvents>> {
        let (clause, args) = filter.clause(2);
        let sql = format!(
            "SELECT volume, path, MIN(artifact), kind, title, MIN(at), MAX(at), COUNT(*), MAX(crypto) FROM events
             WHERE evidence_id = ?1 AND {clause} GROUP BY volume, path, kind, title"
        );
        let bound = params(evidence, &args);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(bound.iter().map(|a| a.as_ref())), |r| {
                Ok((
                    r.get::<_, Option<u32>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                ))
            })?;
            Ok(rows
                .filter_map(|r| r.ok())
                .filter_map(|(volume, path, artifact, kind, title, first, last, count, crypto)| {
                    Some(TitledEvents {
                        volume,
                        path,
                        artifact,
                        kind,
                        title,
                        first: Timestamp::from_unix_micros(first)?,
                        last: Timestamp::from_unix_micros(last)?,
                        count: count as u64,
                        crypto: crypto != 0,
                    })
                })
                .collect())
        })
    }

    /// Host facts of one evidence item under the given keys.
    pub fn facts_with_keys(&self, evidence: EvidenceId, keys: &[&str]) -> Result<Vec<HostFact>> {
        let marks: Vec<String> = (0..keys.len()).map(|i| format!("?{}", i + 2)).collect();
        let sql = format!(
            "SELECT key, value, artifact, source, volume FROM facts WHERE evidence_id = ?1 AND key IN ({}) ORDER BY rowid",
            marks.join(", ")
        );
        let args: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
        let bound = params(evidence, &args);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(bound.iter().map(|a| a.as_ref())), |r| {
                Ok(HostFact { evidence, key: r.get(0)?, value: r.get(1)?, artifact: r.get(2)?, source: r.get(3)?, volume: r.get(4)? })
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
    }

    /// Facts grouped by key (alphabetical), each with its `per_key` most frequent values.
    pub fn fact_groups(&self, evidence: EvidenceId, per_key: usize) -> Result<Vec<FactGroup>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT key, value, COUNT(*), MIN(source) FROM facts WHERE evidence_id = ?1 GROUP BY key, value ORDER BY key, COUNT(*) DESC, value",
            )?;
            let rows = stmt.query_map([evidence.get()], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? as u64, r.get::<_, String>(3)?)))?;
            let mut out: Vec<FactGroup> = Vec::new();
            for (key, value, count, source) in rows.filter_map(|r| r.ok()) {
                if out.last().is_none_or(|g| g.key != key) {
                    out.push(FactGroup { key: key.clone(), total: 0, distinct: 0, values: Vec::new() });
                }
                if let Some(g) = out.last_mut() {
                    g.total += count;
                    g.distinct += 1;
                    if g.values.len() < per_key {
                        g.values.push((value, count, source));
                    }
                }
            }
            Ok(out)
        })
    }
}

pub(crate) fn params<'a>(evidence: EvidenceId, args: &'a [String]) -> Vec<Box<dyn ToSql + 'a>> {
    let mut out: Vec<Box<dyn ToSql + 'a>> = vec![Box::new(evidence.get())];
    out.extend(args.iter().map(|a| Box::new(a.as_str()) as Box<dyn ToSql + 'a>));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_timeline::{EventKind, EventSource, TimelineEvent};

    #[test]
    fn filters_group_and_count() {
        let dir = tempfile::tempdir().unwrap();
        let case = Case::open(&dir.path().join("c.strata")).unwrap();
        let img = dir.path().join("d.img");
        std::fs::write(&img, vec![0u8; 4096]).unwrap();
        let id = case.add_evidence(&img.display().to_string()).unwrap().id;
        let at = |h: i64| Timestamp::from_unix_secs(1_300_000_000 + h * 3600).unwrap();
        let ev = |h, kind, title: &str| TimelineEvent::new(at(h), kind, title, EventSource::new("t", "Users/a/History"));
        let events = [
            ev(0, EventKind::UrlVisited, "http://a"),
            ev(0, EventKind::UrlVisited, "http://b"),
            ev(5, EventKind::UrlVisited, "http://a"),
            ev(1, EventKind::SystemLog, "System start (event log service started)"),
            ev(1, EventKind::SystemLog, "Service event 7036"),
            ev(2, EventKind::Login, "Failed logon: x"),
            ev(3, EventKind::FileModified, "x"),
        ];
        case.write(|w| w.volume_events(id, 2, &events)).unwrap();
        let fact = |key: &str, value: &str| HostFact { evidence: id, volume: Some(2), key: key.into(), value: value.into(), artifact: "t".into(), source: "SYSTEM".into() };
        case.write(|w| w.facts(&[fact("computer_name", "PC"), fact("url", "a"), fact("url", "a"), fact("url", "b")])).unwrap();
        let filter = EventFilter {
            kinds: &["UrlVisited", "Login"],
            titled_kinds: &["SystemLog"],
            title_prefixes: &["System start"],
            excluded_prefixes: &["Failed "],
            ..Default::default()
        };
        let hourly = case.hourly_events(id, &filter).unwrap();
        assert_eq!(hourly.len(), 3);
        assert!(hourly.iter().all(|h| h.volume == Some(2)));
        assert_eq!(hourly.iter().map(|h| h.count).sum::<u64>(), 4);
        let titled = case.titled_events(id, &EventFilter { kinds: &["UrlVisited"], ..Default::default() }).unwrap();
        let a = titled.iter().find(|t| t.title == "http://a").unwrap();
        assert_eq!((a.count, a.first, a.last), (2, at(0), at(5)));
        let facts = case.facts_with_keys(id, &["computer_name"]).unwrap();
        assert_eq!((facts.len(), facts[0].volume), (1, Some(2)));
        let groups = case.fact_groups(id, 1).unwrap();
        let url = groups.iter().find(|g| g.key == "url").unwrap();
        assert_eq!((url.total, url.distinct, url.values.clone()), (3, 2, vec![("a".to_string(), 2, "SYSTEM".to_string())]));
    }
}
