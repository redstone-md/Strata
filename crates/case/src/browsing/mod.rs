//! Browser history as its own subject: the browser events of the timeline (visits, searches,
//! downloads, saved logins and form values, cookies) per disk and profile, folded by site,
//! with the catalogued service behind every host.

mod profile;
mod query;
mod row;
mod sites;

pub use profile::{BrowserFamily, ProfileKey};
pub use query::{BrowserFilter, BrowserQuery, BrowserSegment};
pub use row::{BrowserRow, Credential, DownloadSource};
pub use sites::{BrowserOverview, CookieSite, ProfileSummary, SiteSummary, Span, site_key};

use crate::Case;
use query::Clause;
use sites::{CookieTally, ProfileTally, SiteTally};
use std::collections::HashMap;
use strata_kernel::{EvidenceId, Result, Timestamp};
use strata_timeline::{EventKind, TimelineEvent};

fn kind_of(name: &str) -> Option<EventKind> {
    EventKind::ALL.into_iter().find(|k| format!("{k:?}") == name)
}

/// Profile keys of the files events were read from, worked out once per file.
#[derive(Default)]
struct Profiles(HashMap<(u32, String, String), Option<ProfileKey>>);

impl Profiles {
    fn of(&mut self, evidence: u32, artifact: String, kind: &str, path: String) -> Option<ProfileKey> {
        let family = BrowserFamily::of(&artifact, kind)?;
        self.0
            .entry((evidence, artifact, path))
            .or_insert_with_key(|(e, _, p)| Some(ProfileKey::locate(EvidenceId::new(*e), family, p)))
            .clone()
    }
}

impl Case {
    /// One page of a browser list, oldest first.
    pub fn browser_rows(&self, q: &BrowserQuery) -> Result<Vec<BrowserRow>> {
        let c = Clause::new(&q.filter, q.segment.kinds());
        let mut sql = format!("SELECT id, evidence_id, artifact, kind, data FROM events WHERE {} ORDER BY at, id", c.sql);
        if q.limit > 0 {
            sql += &format!(" LIMIT {} OFFSET {}", q.limit, q.offset);
        }
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(c.params(), |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, u32>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?))
            })?;
            Ok(rows
                .filter_map(|r| r.ok())
                .filter_map(|(id, evidence, artifact, kind, data)| {
                    let family = BrowserFamily::of(&artifact, &kind)?;
                    let event: TimelineEvent = serde_json::from_str(&data).ok()?;
                    Some(BrowserRow { id, evidence: EvidenceId::new(evidence), family, event })
                })
                .collect())
        })
    }

    /// How many rows the whole list has.
    pub fn browser_count(&self, q: &BrowserQuery) -> Result<u64> {
        let c = Clause::new(&q.filter, q.segment.kinds());
        self.with_conn(|conn| conn.query_row(&format!("SELECT COUNT(*) FROM events WHERE {}", c.sql), c.params(), |r| r.get::<_, i64>(0)))
            .map(|n| n as u64)
    }

    /// Profiles (what each holds, its time span and top sites) and visited sites.
    pub fn browser_overview(&self, f: &BrowserFilter) -> Result<BrowserOverview> {
        let mut paths = Profiles::default();
        let mut profiles = ProfileTally::default();
        let all = Clause::all(f);
        let sql = format!(
            "SELECT evidence_id, artifact, path, kind, COUNT(*), SUM(deleted), MIN(at), MAX(at) FROM events WHERE {} GROUP BY 1, 2, 3, 4",
            all.sql
        );
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query(all.params())?;
            while let Some(r) = rows.next()? {
                let kind: String = r.get(3)?;
                let (Some(key), Some(k)) = (paths.of(r.get(0)?, r.get(1)?, &kind, r.get(2)?), kind_of(&kind)) else { continue };
                let (first, last) = (Timestamp::from_unix_micros(r.get(6)?), Timestamp::from_unix_micros(r.get(7)?));
                if let (Some(first), Some(last)) = (first, last) {
                    profiles.count(key, k, r.get::<_, i64>(4)? as u64, r.get::<_, i64>(5)? as u64, first, last);
                }
            }
            Ok(())
        })?;
        let mut sites = SiteTally::default();
        let visits = Clause::new(f, BrowserSegment::History.kinds());
        let sql = format!("SELECT evidence_id, artifact, kind, path, title, at, crypto, deleted FROM events WHERE {}", visits.sql);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query(visits.params())?;
            while let Some(r) = rows.next()? {
                let evidence: u32 = r.get(0)?;
                let kind: String = r.get(2)?;
                let Some(key) = paths.of(evidence, r.get(1)?, &kind, r.get(3)?) else { continue };
                let host = site_key(&r.get::<_, String>(4)?);
                profiles.visit(key, &host);
                if let Some(at) = Timestamp::from_unix_micros(r.get(5)?) {
                    sites.visit(&host, EvidenceId::new(evidence), at, r.get(6)?, r.get(7)?);
                }
            }
            Ok(())
        })?;
        Ok(BrowserOverview { profiles: profiles.finish(), sites: sites.finish(f.crypto_only) })
    }

    /// Cookies grouped by the host that set them.
    pub fn browser_cookie_sites(&self, f: &BrowserFilter) -> Result<Vec<CookieSite>> {
        let c = Clause::new(&BrowserFilter { crypto_only: false, ..f.clone() }, BrowserSegment::Cookies.kinds());
        let sql = format!(
            "SELECT evidence_id, title, CASE WHEN json_valid(data) THEN json_extract(data, '$.detail') END, at FROM events WHERE {}",
            c.sql
        );
        let mut tally = CookieTally::default();
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query(c.params())?;
            while let Some(r) = rows.next()? {
                if let Some(at) = Timestamp::from_unix_micros(r.get(3)?) {
                    let detail: Option<String> = r.get(2)?;
                    tally.add(EvidenceId::new(r.get(0)?), &r.get::<_, String>(1)?, detail.as_deref().unwrap_or(""), at);
                }
            }
            Ok(())
        })?;
        Ok(tally.finish(f.crypto_only))
    }
}

#[cfg(test)]
mod tests;
