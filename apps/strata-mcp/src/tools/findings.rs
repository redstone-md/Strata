//! Findings: keys, seeds, wallets, addresses, identities and the rest, listed the way the app
//! lists them (one row per distinct value), one finding in full, and values found on several
//! disks.

use crate::StrataServer;
use crate::format::{Page, Paging, Reply, btc, fail};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strata_workbench::{AddressBalance, HitCategory, HitQuery, StoredHit, Workbench};

/// Finding category.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
pub enum Category {
    /// WIF, raw hex, DER or mini private keys.
    PrivateKey,
    /// BIP32 xprv/xpub and relatives.
    ExtendedKey,
    /// BIP39 or Electrum seed phrases.
    Mnemonic,
    /// Wallet files (wallet.dat, Electrum, MultiBit, Armory...).
    Wallet,
    Address,
    /// Keywords such as "bitcoin" or "electrum" near data.
    Marker,
    /// File starts and renamed-extension alerts.
    FileSignature,
    /// E-mail addresses, logins, phone numbers.
    Identity,
    Url,
    /// Traces of deleted or lost partitions.
    Partition,
}

impl From<Category> for HitCategory {
    fn from(c: Category) -> Self {
        match c {
            Category::PrivateKey => HitCategory::PrivateKey,
            Category::ExtendedKey => HitCategory::ExtendedKey,
            Category::Mnemonic => HitCategory::Mnemonic,
            Category::Wallet => HitCategory::Wallet,
            Category::Address => HitCategory::Address,
            Category::Marker => HitCategory::Marker,
            Category::FileSignature => HitCategory::FileSignature,
            Category::Identity => HitCategory::Identity,
            Category::Url => HitCategory::Url,
            Category::Partition => HitCategory::Partition,
        }
    }
}

fn categories(list: &[Category]) -> Vec<HitCategory> {
    list.iter().map(|c| (*c).into()).collect()
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListFindingsParams {
    /// Categories to list; all when empty.
    pub categories: Vec<Category>,
    /// Part of the value, label or file path (any case).
    pub text: Option<String>,
    /// Only this disk id.
    pub disk: Option<u32>,
    /// 0..1. Default 0.2, the app's noise floor; lower it to see what triage pushed down.
    pub min_confidence: Option<f32>,
    /// One row per distinct value with the number of places it was found (the app's view).
    /// Default true; false lists every place separately.
    pub group_by_value: Option<bool>,
    /// Include detector details (derived addresses, wallet contents, encryption hashes...).
    /// Default false; `get_finding` always has them.
    pub with_details: bool,
    /// Rows per page, default 50, at most 500.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFindingParams {
    /// Finding id from `list_findings`, `leads` or another tool.
    pub id: i64,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SharedFindingsParams {
    /// Categories to include; keys, wallets, addresses, identities and URLs when empty.
    pub categories: Vec<Category>,
    /// Rows per page, default 50, at most 500.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Serialize)]
pub(crate) struct FileLocation {
    path: String,
    /// `Allocated`, `Deleted`, `Orphan`...
    state: Option<String>,
    offset: Option<u64>,
}

/// One finding, or one distinct value when grouped.
#[derive(Serialize)]
pub(crate) struct Finding {
    id: i64,
    category: String,
    label: String,
    value: String,
    confidence: f32,
    detector: String,
    disk: u32,
    /// Byte offset on the disk.
    disk_offset: u64,
    length: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    volume: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<FileLocation>,
    /// Places this value was found (grouped rows).
    occurrences: u64,
    /// Disks this value was found on (grouped rows).
    disks: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl Finding {
    pub(crate) fn of(h: &StoredHit, with_details: bool) -> Self {
        let details = with_details.then(|| h.hit.details.clone()).filter(|d| !d.is_null());
        Self {
            id: h.id,
            category: format!("{:?}", h.hit.category),
            label: h.hit.label.clone(),
            value: h.hit.value.clone(),
            confidence: (h.hit.confidence.get() * 100.0).round() / 100.0,
            detector: h.hit.detector.clone(),
            disk: h.evidence.get(),
            disk_offset: h.hit.offset,
            length: h.hit.len,
            volume: h.volume,
            file: h.file_path.as_ref().map(|p| FileLocation { path: p.clone(), state: h.file_state.clone(), offset: h.file_offset }),
            occurrences: h.occurrences,
            disks: if h.disks.is_empty() { vec![h.evidence.get()] } else { h.disks.iter().map(|d| d.get()).collect() },
            details,
        }
    }
}

#[derive(Serialize)]
struct FindingDetail {
    finding: Finding,
    /// Every place the same value was found (this one included), up to 200.
    locations: Vec<Finding>,
    /// On-chain state of addresses named in the finding or its details.
    balances: Vec<Balance>,
    /// Leads that point at this finding.
    leads: Vec<LeadMention>,
}

#[derive(Serialize)]
pub(crate) struct Balance {
    address: String,
    balance_sat: u64,
    balance_btc: String,
    funded_sat: u64,
    spent_sat: u64,
    tx_count: u64,
    mempool_delta_sat: i64,
    source: String,
}

impl Balance {
    pub(crate) fn of(b: &AddressBalance) -> Self {
        Self {
            address: b.address.clone(),
            balance_sat: b.balance_sat(),
            balance_btc: btc(b.balance_sat()),
            funded_sat: b.funded_sat,
            spent_sat: b.spent_sat,
            tx_count: b.tx_count,
            mempool_delta_sat: b.mempool_delta_sat,
            source: b.source.clone(),
        }
    }
}

#[derive(Serialize)]
struct LeadMention {
    id: String,
    title: String,
    score: f32,
}

#[derive(Serialize)]
struct Shared {
    category: String,
    value: String,
    disks: Vec<u32>,
    occurrences: u64,
}

const MAX_LOCATIONS: usize = 200;

fn list(wb: &Workbench, p: ListFindingsParams) -> Reply<Page<Finding>> {
    let limit = Paging::LIST.limit(p.limit);
    let q = HitQuery {
        evidence: super::disk(p.disk),
        categories: categories(&p.categories),
        min_confidence: p.min_confidence.unwrap_or(Workbench::NOISE_FLOOR),
        text: p.text,
        limit: limit + 1,
        offset: p.offset,
        group_by_value: p.group_by_value.unwrap_or(true),
        ..HitQuery::default()
    };
    let rows = wb.hits(&q).map_err(fail)?;
    Ok(Page::probed(rows, p.offset, limit).map(|h| Finding::of(&h, p.with_details)))
}

/// Every string anywhere in a JSON value.
fn strings<'a>(v: &'a serde_json::Value, out: &mut Vec<&'a str>) {
    match v {
        serde_json::Value::String(s) => out.push(s),
        serde_json::Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        serde_json::Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

fn detail(wb: &Workbench, id: i64) -> Reply<FindingDetail> {
    let hit = wb
        .hits(&HitQuery { ids: vec![id], ..HitQuery::default() })
        .map_err(fail)?
        .into_iter()
        .next()
        .ok_or_else(|| format!("no finding with id {id}"))?;
    let locations = if hit.hit.value.is_empty() {
        vec![Finding::of(&hit, false)]
    } else {
        let q = HitQuery { categories: vec![hit.hit.category], exact_value: Some(hit.hit.value.clone()), limit: MAX_LOCATIONS, ..HitQuery::default() };
        wb.hits(&q).map_err(fail)?.iter().map(|h| Finding::of(h, false)).collect()
    };
    let known: HashMap<String, AddressBalance> = wb.balances().map_err(fail)?.into_iter().map(|b| (b.address.clone(), b)).collect();
    let mut named = vec![hit.hit.value.as_str()];
    strings(&hit.hit.details, &mut named);
    named.sort_unstable();
    named.dedup();
    let balances = named.iter().filter_map(|a| known.get(*a)).map(Balance::of).collect();
    let leads = wb
        .leads()
        .map_err(fail)?
        .into_iter()
        .filter(|l| l.hits().any(|h| h == id))
        .map(|l| LeadMention { id: l.id, title: l.title, score: l.score })
        .collect();
    Ok(FindingDetail { finding: Finding::of(&hit, true), locations, balances, leads })
}

fn shared(wb: &Workbench, p: SharedFindingsParams) -> Reply<Page<Shared>> {
    let wanted = categories(&p.categories);
    let rows: Vec<Shared> = wb
        .shared_findings()
        .map_err(fail)?
        .into_iter()
        .filter(|s| wanted.is_empty() || wanted.contains(&s.category))
        .map(|s| Shared { category: format!("{:?}", s.category), value: s.value, disks: s.evidence.iter().map(|e| e.get()).collect(), occurrences: s.occurrences })
        .collect();
    Ok(Page::slice(rows, p.offset, Paging::LIST.limit(p.limit)))
}

#[tool_router(router = finding_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "List findings: private keys, extended keys, seed phrases, wallet files, addresses, markers, file \
        signatures and renamed-extension alerts, identities (e-mails, logins), URLs, lost-partition traces. By default one \
        row per distinct value (best place first) with how often and on which disks it was found, sorted by confidence, \
        noise below 0.2 hidden. Each row has the file path, file state (Deleted, Orphan...) and offsets. Values are in clear."
    )]
    pub async fn list_findings(&self, Parameters(p): Parameters<ListFindingsParams>) -> Reply<String> {
        self.query(move |wb| list(wb, p)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "One finding in full: typed details from its detector (derived addresses of a key or seed, wallet \
        contents, encryption hash...), its file and offsets, every other place the same value was found, on-chain \
        balances of the addresses it names, and leads that point at it."
    )]
    pub async fn get_finding(&self, Parameters(p): Parameters<GetFindingParams>) -> Reply<String> {
        self.query(move |wb| detail(wb, p.id)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "Correlation across disks: keys, wallets, addresses, identities and URLs found on more than one disk \
        of the case, most widely shared first. See `file_complements` for files that differ between disks."
    )]
    pub async fn shared_findings(&self, Parameters(p): Parameters<SharedFindingsParams>) -> Reply<String> {
        self.query(move |wb| shared(wb, p)).await
    }
}
