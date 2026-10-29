//! E-mail messages read from mail files (live and deleted) and carved from free space by the
//! app's Mail step. Listing and reading only; attachments are described, not extracted.

use crate::StrataServer;
use crate::format::{Bound, Page, Paging, Reply, date_param, fail, time};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use strata_workbench::{MessageLocation, MessageQuery, MessageRow, MessageState, StoredMessage, Workbench};

/// Body text returned by `get_mail` unless asked for more.
const BODY_CHARS: usize = 20_000;

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ListMailParams {
    /// Words anywhere in subject, sender, recipients or body.
    pub text: Option<String>,
    /// Only messages from, to or copying this e-mail address.
    pub address: Option<String>,
    /// Start date: YYYY, YYYY-MM, YYYY-MM-DD or YYYY-MM-DD HH:MM:SS (UTC).
    pub from: Option<String>,
    /// End date, inclusive of the period it names (`2012` covers all of 2012).
    pub to: Option<String>,
    /// `live` (in a mail file), `deleted` (in a deleted mail file) or `carved` (cut out of free space).
    pub state: Option<String>,
    /// Disk id from case_overview.
    pub disk: Option<u32>,
    /// Rows per page, default 50, at most 500.
    pub limit: Option<usize>,
    pub offset: usize,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct GetMailParams {
    /// Message id from list_mail.
    pub id: i64,
    /// Include every header, not only the envelope.
    pub all_headers: bool,
    /// Characters of body text to return, default 20000.
    pub body_chars: Option<usize>,
}

#[derive(Serialize)]
struct Place {
    state: &'static str,
    /// Mail file and offset inside it, or `free space 0x...` for carved copies.
    place: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    volume: Option<u32>,
}

impl Place {
    fn of(l: &MessageLocation) -> Self {
        Self { state: l.state.name(), place: l.describe(), volume: l.volume }
    }
}

#[derive(Serialize)]
struct MailRow {
    id: i64,
    disk: u32,
    date: Option<String>,
    from: String,
    to: String,
    subject: String,
    attachments: usize,
    #[serde(flatten)]
    place: Place,
    folder: String,
    /// Other copies of the same message on this disk.
    copies: usize,
}

impl MailRow {
    fn of(r: MessageRow) -> Self {
        Self {
            id: r.id,
            disk: r.evidence.get(),
            date: r.at.map(time),
            from: r.from,
            to: r.to,
            subject: r.subject,
            attachments: r.attachments,
            place: Place::of(&r.location),
            folder: r.folder,
            copies: r.copies,
        }
    }
}

#[derive(Serialize)]
struct AttachmentOut {
    name: String,
    mime: String,
    size: u64,
}

#[derive(Serialize)]
struct MailOut {
    #[serde(flatten)]
    row: MailRow,
    message_id: Option<String>,
    cc: Vec<String>,
    body: String,
    /// The body was cut to `body_chars`.
    body_truncated: bool,
    /// The body was converted from an HTML part.
    body_from_html: bool,
    attachment_list: Vec<AttachmentOut>,
    /// Every place this message was found, best copy first.
    places: Vec<Place>,
    /// Damage and decoding problems.
    notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<Vec<(String, String)>>,
}

impl MailOut {
    fn of(m: StoredMessage, p: &GetMailParams) -> Self {
        let limit = p.body_chars.unwrap_or(BODY_CHARS);
        let body_truncated = m.message.body.chars().count() > limit;
        let body = m.message.body.chars().take(limit).collect();
        let mut places = vec![Place::of(&m.row.location)];
        places.extend(m.places.iter().map(Place::of));
        Self {
            message_id: m.message.envelope.message_id.clone(),
            cc: m.message.envelope.cc.iter().map(ToString::to_string).collect(),
            body,
            body_truncated,
            body_from_html: m.message.body_from_html,
            attachment_list: m.message.attachments.iter().map(|a| AttachmentOut { name: a.name.clone(), mime: a.mime.clone(), size: a.size }).collect(),
            places,
            notes: m.message.notes.clone(),
            headers: p.all_headers.then(|| m.message.headers.clone()),
            row: MailRow::of(m.row),
        }
    }
}

fn list_mail(wb: &Workbench, p: ListMailParams) -> Reply<Page<MailRow>> {
    let state = match p.state.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => Some(MessageState::parse(&s.to_ascii_lowercase()).ok_or_else(|| format!("unknown state {s:?}; use live, deleted or carved"))?),
        None => None,
    };
    let limit = Paging::LIST.limit(p.limit);
    let q = MessageQuery {
        evidence: crate::tools::disk(p.disk),
        text: p.text.filter(|t| !t.trim().is_empty()),
        address: p.address.map(|a| a.trim().to_ascii_lowercase()).filter(|a| !a.is_empty()),
        from: date_param(p.from.as_deref(), Bound::Start)?,
        to: date_param(p.to.as_deref(), Bound::End)?,
        state,
        limit: limit + 1,
        offset: p.offset,
    };
    let rows = wb.messages(&q).map_err(fail)?;
    Ok(Page::probed(rows, p.offset, limit).map(MailRow::of))
}

fn get_mail(wb: &Workbench, p: GetMailParams) -> Reply<MailOut> {
    let m = wb.message(p.id).map_err(fail)?.ok_or_else(|| format!("no message with id {}", p.id))?;
    Ok(MailOut::of(m, &p))
}

#[tool_router(router = mail_tools, vis = "pub(crate)")]
impl StrataServer {
    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "E-mail messages recovered from the disks: from mail files (Thunderbird/Opera mbox, .eml, Outlook \
        Express .dbx), from deleted mail files, and carved out of free space. Filter by words, by an address (all mail \
        from, to or copying it), by date range, state or disk. Returns date, sender, recipients, subject, attachment \
        count and where the message was found, oldest first. Read one with get_mail."
    )]
    pub async fn list_mail(&self, Parameters(p): Parameters<ListMailParams>) -> Reply<String> {
        self.query(move |wb| list_mail(wb, p)).await
    }

    #[tool(
        annotations(read_only_hint = true, open_world_hint = false),
        description = "One e-mail message by id: envelope, decoded body text (HTML converted to text), attachment names, \
        types and sizes, every place a copy was found, and damage notes. all_headers adds every header (Received chain, \
        X-Mailer and so on)."
    )]
    pub async fn get_mail(&self, Parameters(p): Parameters<GetMailParams>) -> Reply<String> {
        self.query(move |wb| get_mail(wb, p)).await
    }
}
