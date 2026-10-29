//! The connection map: who the owner is, which accounts, keys, files and addresses belong
//! together, how they reach services and money, and the evidence behind every link.

use crate::StrataServer;
use crate::format::{Reply, btc, fail, time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{Evidence, GraphView, Link, Node, NodeKind, ViewScope, Workbench};

/// Nodes returned unless asked for more, and the most allowed.
const DEFAULT_LIMIT: usize = 40;
const MAX_LIMIT: usize = 200;

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ConnectionsParams {
    /// Entity to centre on: a node key from an earlier answer (`id:...`, `addr:...`, `key:...`,
    /// `acct:...`, `file:...`), or text such as an address, e-mail, login, key or file name.
    /// Omit for the overview of the whole case.
    pub around: Option<String>,
    /// With no `around`: centre on the likely owner instead of returning the overview.
    pub owner: bool,
    /// Steps from the centre, 1 to 4, default 2.
    pub depth: Option<u32>,
    /// Most nodes, default 40, at most 200.
    pub limit: Option<usize>,
    /// Only these kinds besides the centre: identity, account, service, secret, address, file,
    /// disk, message, lead.
    pub kinds: Vec<String>,
}

#[derive(Serialize)]
struct NodeRow {
    key: String,
    kind: &'static str,
    label: String,
    caption: String,
    /// 0..100, closeness to money and ownership.
    score: f32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flags: Vec<&'static str>,
    disks: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<String>,
    /// Stored finding to open with get_finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    finding_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    balance_btc: Option<String>,
    /// Why it ranks where it does.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    why: Vec<String>,
    /// Neighbours not included in this answer.
    #[serde(skip_serializing_if = "is_zero")]
    more: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl NodeRow {
    fn of(n: &Node, more: usize) -> Self {
        let f = n.flags();
        let flags = [(f.owner, "likely_owner"), (f.funded, "funded"), (f.used, "used_on_chain"), (f.deleted, "deleted"), (f.cross_disk, "cross_disk")];
        Self {
            key: n.key().to_string(),
            kind: n.kind().name(),
            label: n.label().to_string(),
            caption: n.caption().to_string(),
            score: n.score().round(),
            flags: flags.into_iter().filter(|(on, _)| *on).map(|(_, name)| name).collect(),
            disks: n.disks().iter().map(|d| d.get()).collect(),
            first_seen: n.first_seen().map(time),
            last_seen: n.last_seen().map(time),
            finding_id: n.hit(),
            balance_btc: n.chain().filter(|c| c.used()).map(|c| btc(c.balance_sat())),
            why: n.why().to_vec(),
            more,
        }
    }
}

#[derive(Serialize)]
struct EdgeRow {
    from: String,
    to: String,
    reason: &'static str,
    count: u64,
}

#[derive(Serialize)]
struct EvidenceRow {
    what: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finding_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lead_id: Option<String>,
}

impl EvidenceRow {
    fn of(e: &Evidence) -> Self {
        let (mut finding_id, mut event_id, mut message_id, mut lead_id) = (None, None, None, None);
        match e {
            Evidence::Finding { hit, .. } => finding_id = Some(*hit),
            Evidence::Trace { hit, event, .. } => (finding_id, event_id) = (*hit, *event),
            Evidence::Message { id, .. } => message_id = Some(*id),
            Evidence::Lead { id, .. } => lead_id = Some(id.clone()),
            Evidence::Transaction { .. } => {}
        }
        Self { what: e.describe(), at: e.at().map(time), finding_id, event_id, message_id, lead_id }
    }
}

#[derive(Serialize)]
struct LinkRow {
    to: String,
    /// Read from the centre: `has an account`, `derived from`, `in the same file as`...
    reason: &'static str,
    count: u64,
    evidence: Vec<EvidenceRow>,
}

impl LinkRow {
    fn of(l: &Link) -> Self {
        Self { to: l.other.key().to_string(), reason: l.phrase(), count: l.count, evidence: l.evidence.iter().map(EvidenceRow::of).collect() }
    }
}

#[derive(Serialize)]
struct ConnectionsReply {
    /// `around` (an ego network) or `overview`.
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    centre: Option<String>,
    nodes: Vec<NodeRow>,
    edges: Vec<EdgeRow>,
    /// Neighbours of the returned nodes that did not fit the limit.
    left_out: usize,
    /// Every link of the centre with its evidence (ego networks only).
    #[serde(skip_serializing_if = "Option::is_none")]
    centre_links: Option<Vec<LinkRow>>,
}

impl ConnectionsReply {
    fn of(mode: &'static str, view: &GraphView) -> Self {
        let key = |i: usize| view.nodes[i].node.key().to_string();
        Self {
            mode,
            centre: view.centre.map(key),
            nodes: view.nodes.iter().map(|v| NodeRow::of(&v.node, v.more)).collect(),
            edges: view.edges.iter().map(|e| EdgeRow { from: key(e.from), to: key(e.to), reason: e.kind.label(), count: e.count }).collect(),
            left_out: view.left_out,
            centre_links: None,
        }
    }
}

fn connections(wb: &Workbench, p: ConnectionsParams) -> Reply<ConnectionsReply> {
    let kinds = p
        .kinds
        .iter()
        .map(|k| NodeKind::parse(k.trim()).ok_or_else(|| format!("unknown kind {k:?}; use identity, account, service, secret, address, file, disk, message or lead")))
        .collect::<Reply<Vec<_>>>()?;
    let scope = ViewScope::new(p.depth.unwrap_or(2), p.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)).kinds(kinds);
    let around = p.around.as_deref().map(str::trim).filter(|a| !a.is_empty());
    let view = match (around, p.owner) {
        (Some(entity), _) => wb.connections_around(entity, &scope).map_err(fail)?.ok_or_else(|| format!("nothing in the connection map matches {entity:?}"))?,
        (None, true) => wb.connections_default(&scope).map_err(fail)?.ok_or("the connection map is empty")?,
        (None, false) => return Ok(ConnectionsReply::of("overview", &wb.connections_overview(&scope).map_err(fail)?)),
    };
    let mut reply = ConnectionsReply::of("around", &view);
    if let Some(centre) = &reply.centre {
        let detail = wb.connection_detail(centre).map_err(fail)?;
        reply.centre_links = detail.map(|d| d.links.iter().take(MAX_LIMIT).map(LinkRow::of).collect());
    }
    Ok(reply)
}

#[tool_router(router = graph_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "The connection map of the case: identities (e-mails, logins), accounts on services, keys, seeds and \
        wallets, addresses with balances, files, disks, mail and leads, linked by typed reasons (has an account, derives, \
        in the same file as, corresponded with, mentions, same transaction, on disk...) with evidence (finding, message, \
        event and lead ids). Nodes are ranked by closeness to money and ownership; the likely owner is flagged. Without \
        `around` it returns the overview of the most important entities; with `around` (a node key or a value such as an \
        address or e-mail) the ego network plus every link of the centre with its evidence. Noise (identities only in \
        system files or in hundreds of files) is left out."
    )]
    pub async fn connections(&self, Parameters(p): Parameters<ConnectionsParams>) -> Reply<String> {
        self.query(move |wb| connections(wb, p)).await
    }
}
