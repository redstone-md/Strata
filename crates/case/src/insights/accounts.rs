//! Stored accounts: the resolver's output (JSON) plus a summary per row (standing, section,
//! strength, reasons, disks) so the Accounts screen and the MCP tool list, filter and count
//! them in SQL. "Seen" listings also take in the byte-level address sightings of
//! `account_mentions` that never became an account.

use super::json;
use crate::Case;
use crate::store::{HIT_COLUMNS, StoredHit, stored_hit};
use rusqlite::{Row, params};
use serde::Serialize;
use strata_accounts::{Account, BULK_PLACE_ADDRESSES, ServiceGroup, ServiceKind, Standing, TraceKind};
use strata_kernel::{EvidenceId, Period, Result, Timestamp};

/// Findings the accounts rebuild reads one by one: every identity and service-URL finding
/// except plain e-mail sightings (those are aggregated into `account_mentions`). Also the
/// condition of the partial index `hits_account_traces`, so it must stay a literal.
pub(crate) const ACCOUNT_TRACE_HITS: &str = "category IN ('Identity', 'Url') AND detector <> 'accounts.email'";

/// One line of an accounts listing, read from the summary columns.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AccountRow {
    pub key: String,
    pub service: String,
    pub service_id: Option<String>,
    /// Service kind label (`exchange`, `mail`...), when catalogued.
    pub service_kind: Option<String>,
    pub identifier: String,
    /// Identifier kind label (`e-mail`, `login`...).
    pub kind: String,
    pub group: ServiceGroup,
    pub standing: Standing,
    /// 0..1, see [`Account::strength`].
    pub strength: f32,
    /// A saved password is available.
    pub secret: bool,
    /// Why the account is listed, strongest first.
    pub reasons: Vec<TraceKind>,
    /// Traces behind the account (for a bare sighting: times the address was found).
    pub traces: u64,
    pub disks: Vec<EvidenceId>,
    pub first_seen: Option<Timestamp>,
    pub last_seen: Option<Timestamp>,
    /// Times the address was also found byte-level on the disks.
    pub mentions: u64,
    /// A bare byte-level sighting, not a resolved account (details: [`Case::mention`]).
    pub mention_only: bool,
}

impl AccountRow {
    /// On a service that holds funds (exchange, web wallet, pool, faucet, e-money...).
    pub fn holds_funds(&self) -> bool {
        self.service_kind.as_deref().and_then(ServiceKind::from_label).is_some_and(ServiceKind::holds_funds)
    }

    fn read(r: &Row) -> rusqlite::Result<Self> {
        let secs = |i: usize| r.get::<_, Option<i64>>(i).map(|v| v.and_then(Timestamp::from_unix_secs));
        let reasons: String = r.get(10)?;
        let disks: String = r.get(12)?;
        Ok(Self {
            key: r.get(0)?,
            service: r.get(1)?,
            service_id: r.get(2)?,
            service_kind: r.get(3)?,
            identifier: r.get(4)?,
            kind: r.get(5)?,
            group: r.get::<_, Option<String>>(6)?.as_deref().and_then(ServiceGroup::from_id).unwrap_or(ServiceGroup::Other),
            standing: Standing::from_rank(r.get::<_, Option<i64>>(7)?.unwrap_or(Standing::Seen.rank())),
            strength: r.get::<_, f64>(8)? as f32,
            secret: r.get::<_, i64>(9)? != 0,
            reasons: reasons.split(',').filter_map(trace_from_id).collect(),
            traces: r.get::<_, i64>(11)?.max(0) as u64,
            disks: parse_disks(&disks),
            first_seen: secs(13)?,
            last_seen: secs(14)?,
            mentions: r.get::<_, i64>(15)?.max(0) as u64,
            mention_only: r.get::<_, i64>(16)? != 0,
        })
    }
}

/// What to list. Default: every used account, strongest first.
#[derive(Debug, Clone, Default)]
pub struct AccountQuery {
    /// The accounts only seen in data (and bare address sightings) instead of the used ones.
    pub seen: bool,
    /// With `seen`: also addresses found only in dumps and lists.
    pub include_bulk: bool,
    pub group: Option<ServiceGroup>,
    /// Part of the identifier or the service name (any case).
    pub text: Option<String>,
    /// Accounts whose seen window misses the period are left out; undated ones stay.
    pub period: Option<Period>,
    /// 0: no limit.
    pub limit: usize,
    pub offset: usize,
}

const ROW_COLUMNS: &str = "key, service, service_id, service_kind, identifier, kind, section, standing, strength, secret, reasons, traces, disks,
    first_seen, last_seen, mentions";

impl AccountQuery {
    /// The rows to filter: used accounts, or seen accounts plus bare sightings.
    fn source(&self) -> String {
        let accounts = |standing: &str| format!("SELECT {ROW_COLUMNS}, 0 AS mention_only FROM accounts WHERE {standing}");
        if !self.seen {
            return accounts("standing = 2");
        }
        let bulk = if self.include_bulk { String::new() } else { format!(" AND density < {BULK_PLACE_ADDRESSES}") };
        format!(
            "{} UNION ALL
             SELECT 'mention|' || address, substr(address, instr(address, '@') + 1), NULL, NULL, found_as, 'e-mail', 'mail',
                    CASE WHEN density >= {BULK_PLACE_ADDRESSES} THEN 0 ELSE 1 END, {}, 0, 'mention', hits, disks, NULL, NULL, hits, 1
             FROM account_mentions m WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.identifier = m.address){bulk}",
            accounts("IFNULL(standing, 1) < 2"),
            TraceKind::Mention.weight()
        )
    }

    /// `SELECT … FROM (source) WHERE filters` with its arguments.
    fn sql(&self, select: &str) -> (String, Vec<String>) {
        let mut sql = format!("SELECT {select} FROM ({}) WHERE 1 = 1", self.source());
        let mut args = Vec::new();
        if let Some(g) = self.group {
            args.push(g.id().to_string());
            sql += &format!(" AND section = ?{}", args.len());
        }
        if let Some(t) = self.text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            let escaped = t.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
            args.push(format!("%{escaped}%"));
            let n = args.len();
            sql += &format!(" AND (identifier LIKE ?{n} ESCAPE '\\' OR service LIKE ?{n} ESCAPE '\\')");
        }
        if let Some(p) = self.period.filter(|p| !p.is_all()) {
            let from = p.from.map_or(i64::MIN, |t| t.unix_secs());
            let to = p.to.map_or(i64::MAX, |t| t.unix_secs());
            sql += &format!(
                " AND ((first_seen IS NULL AND last_seen IS NULL)
                   OR (IFNULL(first_seen, last_seen) < {to} AND IFNULL(last_seen, first_seen) >= {from}))"
            );
        }
        (sql, args)
    }
}

fn trace_from_id(id: &str) -> Option<TraceKind> {
    serde_json::from_value(serde_json::Value::String(id.trim().to_string())).ok()
}

fn trace_id(kind: TraceKind) -> String {
    serde_json::to_value(kind).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

pub(crate) fn parse_disks(text: &str) -> Vec<EvidenceId> {
    let mut disks: Vec<EvidenceId> = text.split(',').filter_map(|d| d.trim().parse().ok()).map(EvidenceId::new).collect();
    disks.sort();
    disks.dedup();
    disks
}

impl Case {
    /// Replace every stored account with a fresh resolution. Run after
    /// [`Case::refresh_mentions`] so each account knows how often its address was sighted.
    pub fn replace_accounts(&self, accounts: &[Account]) -> Result<usize> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            tx.execute("DELETE FROM accounts", [])?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO accounts (key, service, service_id, service_kind, identifier, kind, first_seen, last_seen, confidence, data,
                     standing, section, strength, secret, reasons, traces, disks, mentions)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                             IFNULL((SELECT hits FROM account_mentions WHERE address = lower(?5)), 0))",
                )?;
                for a in accounts {
                    let reasons: Vec<String> = a.reasons().into_iter().map(trace_id).collect();
                    let disks: Vec<String> = a.disks().iter().map(|d| d.get().to_string()).collect();
                    stmt.execute(params![
                        a.key(),
                        a.service(),
                        a.service_id(),
                        a.service_kind().map(|k| k.label()),
                        a.identifier(),
                        a.kind().label(),
                        a.first_seen().map(|t| t.unix_secs()),
                        a.last_seen().map(|t| t.unix_secs()),
                        a.confidence(),
                        json(a),
                        a.standing().rank(),
                        a.group().id(),
                        a.strength(),
                        a.has_secret(),
                        reasons.join(","),
                        a.sources().len() as i64,
                        disks.join(","),
                    ])?;
                }
            }
            tx.commit()?;
            Ok(accounts.len())
        })
    }

    /// Stored accounts in resolver order (used ones first, fund-holding services first).
    pub fn accounts(&self) -> Result<Vec<Account>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT data FROM accounts ORDER BY rowid")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            Ok(rows.filter_map(|r| r.ok()).filter_map(|d| serde_json::from_str(&d).ok()).collect())
        })
    }

    /// One stored account with all its traces.
    pub fn account(&self, key: &str) -> Result<Option<Account>> {
        self.with_conn(|conn| {
            let data: Option<String> = conn.query_row("SELECT data FROM accounts WHERE key = ?1", [key], |r| r.get(0)).map(Some).or_else(none_if_missing)?;
            Ok(data.and_then(|d| serde_json::from_str(&d).ok()))
        })
    }

    /// Summary rows, used accounts by strength or seen ones by how close they come to use.
    pub fn account_rows(&self, q: &AccountQuery) -> Result<Vec<AccountRow>> {
        let (mut sql, args) = q.sql(&format!("{ROW_COLUMNS}, mention_only"));
        sql += if q.seen {
            " ORDER BY standing DESC, strength DESC, mentions DESC, identifier"
        } else {
            " ORDER BY strength DESC, secret DESC, IFNULL(last_seen, 0) DESC, service, identifier"
        };
        if q.limit > 0 {
            sql += &format!(" LIMIT {} OFFSET {}", q.limit, q.offset);
        }
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), AccountRow::read)?;
            rows.collect()
        })
    }

    /// How many rows [`Case::account_rows`] would list without a limit.
    pub fn account_count(&self, q: &AccountQuery) -> Result<u64> {
        let (sql, args) = q.sql("COUNT(*)");
        self.with_conn(|conn| conn.query_row(&sql, rusqlite::params_from_iter(args.iter()), |r| r.get::<_, i64>(0)).map(|n| n.max(0) as u64))
    }

    /// Accounts resolved by an older version (no standing yet): a rebuild sorts them.
    pub fn accounts_need_rebuild(&self) -> Result<bool> {
        self.with_conn(|conn| conn.query_row("SELECT EXISTS (SELECT 1 FROM accounts WHERE standing IS NULL)", [], |r| r.get(0)))
    }

    /// Identity and service-URL findings that may name an account (see [`ACCOUNT_TRACE_HITS`]).
    pub fn account_trace_hits(&self) -> Result<Vec<StoredHit>> {
        let sql = format!("SELECT {HIT_COLUMNS} FROM hits INDEXED BY hits_account_traces WHERE {ACCOUNT_TRACE_HITS} ORDER BY id");
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], stored_hit)?;
            rows.collect()
        })
    }
}

pub(crate) fn none_if_missing<T>(e: rusqlite::Error) -> rusqlite::Result<Option<T>> {
    match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        e => Err(e),
    }
}
