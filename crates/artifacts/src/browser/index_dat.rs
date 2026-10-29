//! Internet Explorer / old Edge `index.dat` (MSIE cache file 5.2): History.IE5 master, daily
//! and weekly containers, Content.IE5 cache and Cookies.
//!
//! Every 0x80-aligned block is checked for `URL `/`LEAK`/`REDR` records, so records that fell
//! out of the hash table (deleted, superseded) are recovered too; those are marked `unlinked`.

use crate::results::Recorder;
use crate::text::{ansi_at, filetime_at, parse_iso8601};
use std::collections::HashSet;
use strata_kernel::bytes::u32_le;
use strata_kernel::{ByteRange, Confidence, Damage, Timestamp};
use strata_timeline::EventKind;

pub(crate) const SIGNATURE: &[u8] = b"Client UrlCache MMF Ver ";
const BLOCK: usize = 0x80;
const FIRST_BLOCK: usize = 0x4000;
const HASH_OFFSET: usize = 0x20;

pub(crate) struct IndexDat<'a> {
    data: &'a [u8],
}

/// Which container a record came from, decided by its location prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Container {
    /// `Visited: user@url` (History.IE5 master).
    History,
    /// `:YYYYMMDDYYYYMMDD: user@url` (MSHist01… daily or weekly).
    Periodic { weekly: bool },
    /// `Cookie:user@host/path`.
    Cookie,
    /// Plain URL (Content.IE5 cache, DOMStore).
    Cache,
}

impl<'a> IndexDat<'a> {
    pub fn is_index_dat(data: &[u8]) -> bool {
        data.starts_with(SIGNATURE)
    }

    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn parse(&self, rec: &mut Recorder) {
        if !Self::is_index_dat(self.data) {
            rec.damage(Damage::corrupt(ByteRange::new(0, 28), "index.dat signature missing, scanning records anyway"));
        }
        let declared = u32_le(self.data, 0x1C).unwrap_or(0) as usize;
        if declared > self.data.len() {
            rec.damage(Damage::truncated(format!("index.dat declares {declared} bytes, have {}", self.data.len())));
        }
        let linked = self.hash_linked(rec);
        let mut off = FIRST_BLOCK.min(self.data.len());
        while off + 8 <= self.data.len() {
            let blocks = u32_le(self.data, off + 4).unwrap_or(0) as usize;
            let step = match &self.data[off..off + 4] {
                b"URL " | b"LEAK" => self.url_record(off, blocks, linked.contains(&off), rec),
                b"REDR" => self.redirect(off, rec),
                _ => None,
            };
            let span = step.map_or(BLOCK, |_| blocks.clamp(1, 1024) * BLOCK);
            off += span;
        }
    }

    /// Record offsets referenced from the hash-table chain.
    fn hash_linked(&self, rec: &mut Recorder) -> HashSet<usize> {
        let mut out = HashSet::new();
        let mut table = u32_le(self.data, HASH_OFFSET).unwrap_or(0) as usize;
        let mut seen = HashSet::new();
        while table != 0 && seen.insert(table) {
            if self.data.get(table..table + 4) != Some(b"HASH") {
                rec.damage(Damage::corrupt(ByteRange::new(table as u64, 4), "index.dat hash table missing"));
                break;
            }
            let size = (u32_le(self.data, table + 4).unwrap_or(0) as usize).saturating_mul(BLOCK);
            let end = (table + size).min(self.data.len());
            let mut e = table + 16;
            while e + 8 <= end {
                let rec_off = u32_le(self.data, e + 4).unwrap_or(0) as usize;
                if rec_off >= FIRST_BLOCK && rec_off % BLOCK == 0 {
                    out.insert(rec_off);
                }
                e += 8;
            }
            table = u32_le(self.data, table + 8).unwrap_or(0) as usize;
        }
        out
    }

    fn url_record(&self, off: usize, blocks: usize, linked: bool, rec: &mut Recorder) -> Option<()> {
        let size = blocks.checked_mul(BLOCK).filter(|s| *s >= 0x68)?;
        let rec_bytes = self.data.get(off..(off + size).min(self.data.len()))?;
        let modified = filetime_at(rec_bytes, 0x08);
        let accessed = filetime_at(rec_bytes, 0x10);
        let loc_off = u32_le(rec_bytes, 0x34)? as usize;
        let location = ansi_at(rec_bytes, loc_off, size.saturating_sub(loc_off).min(4096));
        if location.is_empty() {
            return Some(());
        }
        let hits = u32_le(rec_bytes, 0x54).unwrap_or(0);
        let leak = &rec_bytes[..4] == b"LEAK";
        let (container, user, url) = split_location(&location);
        if url.starts_with(":Host:") {
            return Some(());
        }
        let (at, kind) = match container {
            Container::History => (accessed, EventKind::UrlVisited),
            Container::Periodic { weekly: false } => (modified.or(accessed), EventKind::UrlVisited),
            Container::Periodic { weekly: true } => (accessed.or(modified), EventKind::UrlVisited),
            Container::Cookie => (modified.or(accessed), EventKind::Cookie),
            Container::Cache => (accessed.or(modified), EventKind::UrlVisited),
        };
        let detail = format!(
            "IE {:?}; last modified {}; last access {}; hits {hits}{}",
            container,
            fmt_opt(modified),
            fmt_opt(accessed),
            if leak { "; LEAK record" } else { "" }
        );
        let Some(mut event) = rec.make(at, kind, url) else {
            rec.fact("url", location);
            return Some(());
        };
        event = event.with_detail(detail);
        if let Some(user) = user {
            event.set_actor(user);
        }
        if matches!(container, Container::Periodic { weekly: true }) {
            event = event.with_confidence(Confidence::MEDIUM);
        }
        if !linked {
            event.add_tag("unlinked");
            event = event.with_confidence(Confidence::MEDIUM);
        }
        rec.push(event);
        Some(())
    }

    fn redirect(&self, off: usize, rec: &mut Recorder) -> Option<()> {
        let url = ansi_at(self.data, off + 0x10, 2048);
        rec.fact("redirect", url);
        Some(())
    }
}

fn fmt_opt(t: Option<Timestamp>) -> String {
    t.map_or_else(|| "-".to_string(), |t| t.to_string())
}

/// Split `prefix user@url` into container, user and URL.
fn split_location(loc: &str) -> (Container, Option<String>, String) {
    let user_url = |rest: &str| match rest.split_once('@') {
        Some((u, url)) if !u.contains('/') && !u.contains(':') => (Some(u.trim().to_string()), url.to_string()),
        _ => (None, rest.to_string()),
    };
    if let Some(rest) = loc.strip_prefix("Visited:") {
        let (u, url) = user_url(rest.trim_start());
        return (Container::History, u, url);
    }
    if let Some(rest) = loc.strip_prefix("Cookie:") {
        let (u, host) = user_url(rest);
        return (Container::Cookie, u, host);
    }
    if loc.starts_with(':') && loc.len() > 18 && loc.is_char_boundary(18) && loc.as_bytes().get(17) == Some(&b':') {
        let range = |r: std::ops::Range<usize>| loc.get(r).and_then(parse_iso8601);
        let (from, to) = (range(1..9), range(9..17));
        let weekly = matches!((from, to), (Some(a), Some(b)) if b.unix_secs() - a.unix_secs() > 86_400);
        let (u, url) = user_url(loc[18..].trim_start());
        return (Container::Periodic { weekly }, u, url);
    }
    (Container::Cache, None, loc.to_string())
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// Build an index.dat with one hash table and the given `(location, filetime)` URL records;
    /// the last record is left out of the hash table (unlinked).
    pub fn build(records: &[(&str, u64)]) -> Vec<u8> {
        let mut d = vec![0u8; FIRST_BLOCK];
        d[..28].copy_from_slice(b"Client UrlCache MMF Ver 5.2\0");
        // Hash table as the first block run.
        let hash = FIRST_BLOCK;
        d.resize(hash + 8 * BLOCK, 0);
        d[hash..hash + 4].copy_from_slice(b"HASH");
        d[hash + 4..hash + 8].copy_from_slice(&8u32.to_le_bytes());
        d[HASH_OFFSET..HASH_OFFSET + 4].copy_from_slice(&(hash as u32).to_le_bytes());
        for (i, (loc, ft)) in records.iter().enumerate() {
            let off = d.len();
            let mut r = vec![0u8; 4 * BLOCK];
            r[..4].copy_from_slice(b"URL ");
            r[4..8].copy_from_slice(&4u32.to_le_bytes());
            r[8..16].copy_from_slice(&ft.to_le_bytes());
            r[16..24].copy_from_slice(&ft.to_le_bytes());
            r[0x34..0x38].copy_from_slice(&0x68u32.to_le_bytes());
            r[0x54..0x58].copy_from_slice(&3u32.to_le_bytes());
            r[0x68..0x68 + loc.len()].copy_from_slice(loc.as_bytes());
            d.extend_from_slice(&r);
            if i + 1 < records.len() {
                let e = hash + 16 + 8 * i;
                d[e + 4..e + 8].copy_from_slice(&(off as u32).to_le_bytes());
            }
        }
        let len = d.len() as u32;
        d[0x1C..0x20].copy_from_slice(&len.to_le_bytes());
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2011-12-15 12:00:00 UTC
    const FT: u64 = 129_684_240_000_000_000;

    #[test]
    fn parses_history_cookie_and_unlinked() {
        let data = testutil::build(&[
            ("Visited: Admin@http://www.yandex.ru/yandsearch?text=bitcoin", FT),
            (":2011121520111216: Admin@http://mail.ru/", FT),
            ("Cookie:admin@mail.ru/", FT),
            ("Visited: Admin@https://mtgox.com/", FT),
        ]);
        let mut rec = Recorder::new("ie.index_dat");
        IndexDat::new(&data).parse(&mut rec);
        let out = rec.finish();
        assert_eq!(out.events.len(), 4, "{:?}", out.events);
        let first = &out.events[0];
        assert_eq!(first.title(), "http://www.yandex.ru/yandsearch?text=bitcoin");
        assert_eq!(first.actor(), Some("Admin"));
        assert_eq!(first.at().to_string(), "2011-12-15 12:00:00");
        assert_eq!(out.events[2].kind(), EventKind::Cookie);
        assert!(out.events[3].has_tag("unlinked"));
        assert!(!out.events[0].has_tag("unlinked"));
    }

    #[test]
    fn truncated_and_garbage() {
        let data = testutil::build(&[("Visited: A@http://x.example/", FT)]);
        for cut in [0, 10, 0x30, FIRST_BLOCK + 3, FIRST_BLOCK + 8 * BLOCK + 0x40, data.len() - 1] {
            let mut rec = Recorder::new("t");
            IndexDat::new(&data[..cut]).parse(&mut rec);
        }
        let mut junk = data.clone();
        for (i, b) in junk.iter_mut().enumerate().skip(28) {
            *b = (i * 13 % 256) as u8;
        }
        let mut rec = Recorder::new("t");
        IndexDat::new(&junk).parse(&mut rec);
    }
}
