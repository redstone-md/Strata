//! Account listings, address sightings and mailbox owners on synthetic data.

use super::tests::{case_with_disk, ts};
use crate::{AccountQuery, Attribution, Case, FileRef};
use strata_accounts::{AccountResolver, AccountSource, IdentifierKind, Observation, ServiceGroup, SourceRef, Standing, TraceKind};
use strata_fs::EntryState;
use strata_kernel::scan::{Hit, HitCategory};
use strata_kernel::{EvidenceId, Period, Timestamp};

fn observation(disk: EvidenceId, service: Option<&str>, id: &str, kind: IdentifierKind, trace: TraceKind, hit: i64, at: i64) -> Observation {
    Observation {
        service: service.map(str::to_string),
        identifier: id.into(),
        kind,
        source: AccountSource { evidence: disk, origin: SourceRef::Hit(hit), detail: trace.label().into(), at: Timestamp::from_unix_secs(at), trace },
        first_seen: None,
        last_seen: None,
        confidence: 0.8,
    }
}

fn email_hit(value: &str, offset: u64, file: Option<&str>) -> (Hit, Attribution) {
    let hit = Hit::new("accounts.email", HitCategory::Identity, offset, value.len()).label("e-mail").value(value);
    let file = file.map(|p| FileRef { path: p.into(), state: EntryState::Allocated, file_offset: 0 });
    (hit, Attribution { volume: file.as_ref().map(|_| 0), file })
}

/// A dump of 60 addresses, a note with two, one address in free space.
fn store_sightings(case: &Case, disk: EvidenceId) {
    let mut hits: Vec<(Hit, Attribution)> = (0..60).map(|i| email_hit(&format!("list{i}@example.net"), 1000 + i * 40, Some("dump/list.txt"))).collect();
    hits.push(email_hit("Owner.Test@example.com", 9000, Some("Users/a/notes.txt")));
    hits.push(email_hit("list7@example.net", 9100, Some("Users/a/notes.txt")));
    hits.push(email_hit("owner.test@example.com", 5 << 20, None));
    hits.push(email_hit("friend@example.org", 9 << 20, None));
    case.store_hits(disk, &hits).unwrap();
}

#[test]
fn sightings_aggregate_per_address_and_flag_bulk() {
    let dir = tempfile::tempdir().unwrap();
    let (case, disk) = case_with_disk(dir.path());
    store_sightings(&case, disk);
    assert_eq!(case.refresh_mentions().unwrap(), Some(62));
    assert_eq!(case.refresh_mentions().unwrap(), None, "unchanged findings are not aggregated again");

    let owner = case.mention("OWNER.test@example.com").unwrap().unwrap();
    assert_eq!((owner.hits, owner.places, owner.density), (2, 2, 1));
    assert!(!owner.is_bulk());
    assert_eq!(owner.disks, [disk]);
    assert!(case.mention("list3@example.net").unwrap().unwrap().is_bulk());
    assert!(!case.mention("list7@example.net").unwrap().unwrap().is_bulk(), "also in a small note: a contact");

    let seen = AccountQuery { seen: true, ..Default::default() };
    assert_eq!(case.account_count(&seen).unwrap(), 3);
    let rows = case.account_rows(&seen).unwrap();
    assert!(rows.iter().all(|r| r.mention_only && r.standing == Standing::Seen));
    assert_eq!(rows[0].identifier.to_lowercase(), "owner.test@example.com", "most sighted first");
    assert_eq!(case.account_count(&AccountQuery { include_bulk: true, ..seen.clone() }).unwrap(), 62);
    let text = AccountQuery { text: Some("FRIEND".into()), ..seen };
    assert_eq!(case.account_rows(&text).unwrap().len(), 1);
}

#[test]
fn used_accounts_list_by_strength_with_reasons() {
    let dir = tempfile::tempdir().unwrap();
    let (case, disk) = case_with_disk(dir.path());
    store_sightings(&case, disk);
    case.refresh_mentions().unwrap();
    let mut r = AccountResolver::new();
    r.observe(observation(disk, Some("mtgox.com"), "gox_tester", IdentifierKind::Login, TraceKind::SavedPassword, 1, 1_310_000_000));
    r.observe(observation(disk, None, "owner.test@example.com", IdentifierKind::Email, TraceKind::MailAccount, 2, 1_400_000_000));
    r.observe(observation(disk, Some("steamcommunity.com"), "gamer_test", IdentifierKind::Login, TraceKind::Cookie, 3, 1_420_000_000));
    r.observe(observation(disk, None, "friend@example.org", IdentifierKind::Email, TraceKind::Correspondent, 4, 1_420_000_000));
    let accounts = r.finish();
    case.replace_accounts(&accounts).unwrap();
    assert!(!case.accounts_need_rebuild().unwrap());

    let used = case.account_rows(&AccountQuery::default()).unwrap();
    let ids: Vec<&str> = used.iter().map(|r| r.identifier.as_str()).collect();
    assert_eq!(ids, ["gox_tester", "owner.test@example.com", "gamer_test"], "strongest first, correspondents left out");
    let gox = &used[0];
    assert!(gox.secret && gox.group == ServiceGroup::Crypto && gox.reasons == [TraceKind::SavedPassword]);
    assert_eq!(gox.disks, [disk]);
    let mailbox = &used[1];
    assert_eq!((mailbox.group, mailbox.mentions), (ServiceGroup::Mail, 2), "knows its byte-level sightings");
    assert_eq!(used[2].group, ServiceGroup::Games);

    let crypto = AccountQuery { group: Some(ServiceGroup::Crypto), ..Default::default() };
    assert_eq!(case.account_count(&crypto).unwrap(), 1);
    let period = Period { from: Some(ts(1_390_000_000)), to: None };
    assert_eq!(case.account_count(&AccountQuery { period: Some(period), ..Default::default() }).unwrap(), 2);

    // The correspondent is a seen account; its sighting row is not listed twice.
    let seen = case.account_rows(&AccountQuery { seen: true, ..Default::default() }).unwrap();
    let friend: Vec<_> = seen.iter().filter(|r| r.identifier == "friend@example.org").collect();
    assert_eq!(friend.len(), 1);
    assert!(!friend[0].mention_only && friend[0].reasons == [TraceKind::Correspondent]);
    assert!(!seen.iter().any(|r| r.identifier.eq_ignore_ascii_case("owner.test@example.com")), "used accounts are not 'seen'");

    let full = case.account(&gox.key).unwrap().unwrap();
    assert_eq!(full.identifier(), "gox_tester");
    assert!(case.account("nope|x").unwrap().is_none());
}

#[test]
fn trace_hits_skip_plain_sightings() {
    let dir = tempfile::tempdir().unwrap();
    let (case, disk) = case_with_disk(dir.path());
    store_sightings(&case, disk);
    let login = Hit::new("accounts.login", HitCategory::Identity, 77, 8).label("login (url)").value("gox_tester");
    case.store_hits(disk, &[(login, Attribution::default())]).unwrap();
    let hits = case.account_trace_hits().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].hit.value, "gox_tester");
}

#[test]
fn mailbox_owner_and_sent_mail() {
    let dir = tempfile::tempdir().unwrap();
    let (case, disk) = case_with_disk(dir.path());
    let message = |id: i64, folder: &str, path: &str, from: &str, to: &str, at: i64| {
        case.with_write(|c| {
            c.execute(
                "INSERT INTO messages (id, evidence_id, fingerprint, state, container, file_path, folder, offset, len, at, sender, recipients, subject, body, attachments, data, places)
                 VALUES (?1, ?2, ?1, 'live', 'mbox', ?3, ?4, 0, 0, ?5, ?6, ?7, '', '', 0, '{}', '[]')",
                rusqlite::params![id, disk.get(), path, folder, at, from, to],
            )?;
            for a in [from, to] {
                let addr = a.rsplit('<').next().unwrap_or(a).trim_end_matches('>');
                c.execute("INSERT OR IGNORE INTO message_addresses (address, message) VALUES (?1, ?2)", rusqlite::params![addr, id])?;
            }
            Ok(())
        })
        .unwrap();
    };
    let inbox = "home/a/.thunderbird/p/ImapMail/mail.example.com/INBOX";
    message(1, "INBOX", inbox, "Shop <news@shop.example.net>", "Owner <Owner.Test@example.com>", 1_300_000_000);
    message(2, "INBOX", inbox, "Friend <friend@example.org>", "owner.test@example.com", 1_310_000_000);
    message(3, "INBOX", inbox, "Shop <news@shop.example.net>", "Owner.Test@example.com", 1_320_000_000);
    message(4, "Sent", "home/a/.thunderbird/p/ImapMail/mail.example.com/INBOX.sbd/Sent", "Owner <owner.test@example.com>", "friend@example.org", 1_330_000_000);
    let traces = case.mailbox_traces().unwrap();
    let owner = traces.iter().find(|t| !t.sent).unwrap();
    assert_eq!((owner.address.as_str(), owner.messages, owner.total), ("owner.test@example.com", 3, 3));
    assert_eq!(owner.first, Some(ts(1_300_000_000)));
    assert_eq!(traces.iter().filter(|t| !t.sent).count(), 1, "the shop sends often but is not a recipient");
    let sent = traces.iter().find(|t| t.sent).unwrap();
    assert_eq!((sent.address.as_str(), sent.messages), ("owner.test@example.com", 1));
}
