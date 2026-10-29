//! Mail for the connection graph: envelopes (who wrote to whom), and message bodies naming an
//! address, key or identity the graph already knows. Bodies are read live mailboxes first and
//! only their first bytes.

use rusqlite::Connection;
use std::collections::BTreeSet;
use strata_graph::{Limits, MailFact, MentionFact};
use strata_kernel::{EvidenceId, Timestamp};

/// Addresses of a stored party list (`Name <a@b>, c@d`), lowercased.
fn addresses(parties: &str) -> Vec<String> {
    parties
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            let inner = match (p.rfind('<'), p.rfind('>')) {
                (Some(a), Some(b)) if a < b => &p[a + 1..b],
                _ => p,
            };
            let inner = inner.trim();
            (inner.contains('@') && !inner.contains(char::is_whitespace)).then(|| inner.to_ascii_lowercase())
        })
        .collect()
}

pub(super) fn messages(conn: &Connection, limits: &Limits) -> rusqlite::Result<Vec<MailFact>> {
    let mut stmt = conn.prepare("SELECT id, evidence_id, at, state, sender, recipients, subject FROM messages ORDER BY id LIMIT ?1")?;
    let rows = stmt.query_map([limits.messages as i64], |r| {
        Ok(MailFact {
            id: r.get(0)?,
            disk: EvidenceId::new(r.get(1)?),
            at: r.get::<_, Option<i64>>(2)?.and_then(Timestamp::from_unix_secs),
            live: r.get::<_, String>(3)? == "live",
            from: addresses(&r.get::<_, String>(4)?),
            to: addresses(&r.get::<_, String>(5)?),
            subject: r.get(6)?,
        })
    })?;
    rows.collect()
}

/// Words of a body that may be an address, key, e-mail or login.
fn words(body: &str) -> impl Iterator<Item = &str> {
    body.split(|c: char| !(c.is_ascii_alphanumeric() || "@._+-".contains(c))).map(|w| w.trim_matches(['.', '-'])).filter(|w| (4..=120).contains(&w.len()))
}

/// Messages whose body names one of `targets` (case-sensitive for addresses and keys,
/// case-folded for identities).
pub(super) fn mentions(conn: &Connection, targets: &BTreeSet<String>, limits: &Limits) -> rusqlite::Result<Vec<MentionFact>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT id, substr(body, 1, ?1) FROM messages
         ORDER BY CASE state WHEN 'live' THEN 0 WHEN 'deleted' THEN 1 ELSE 2 END, id LIMIT ?2",
    )?;
    let mut rows = stmt.query([limits.body_bytes as i64, limits.bodies as i64])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let id: i64 = r.get(0)?;
        let body: String = r.get::<_, Option<String>>(1)?.unwrap_or_default();
        let mut found = BTreeSet::new();
        for w in words(&body) {
            if targets.contains(w) {
                found.insert(w.to_string());
            } else if w.contains('@') || w.chars().any(|c| c.is_ascii_uppercase()) {
                let folded = w.to_ascii_lowercase();
                if targets.contains(&folded) {
                    found.insert(folded);
                }
            }
        }
        out.extend(found.into_iter().map(|value| MentionFact { message: id, value }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_party_lists_and_body_words() {
        assert_eq!(addresses("Olga <Olga.Test@Example.ru>, ivan@example.ru, Shop"), ["olga.test@example.ru", "ivan@example.ru"]);
        let body = "Send to 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH. Login: gox_tester, mail olga@example.ru.";
        let w: Vec<&str> = words(body).collect();
        assert!(w.contains(&"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") && w.contains(&"gox_tester") && w.contains(&"olga@example.ru"));
    }
}
