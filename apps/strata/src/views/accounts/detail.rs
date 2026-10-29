//! Side panel for one account: why it is (or is not) the owner's, every trace with a link to
//! its finding or day, how often the address was found byte-level, and the same name on
//! other services. A bare sighting lists the places the address was found.

use super::day;
use super::list::reasons_text;
use crate::format;
use crate::nav::{ConnectTo, Jump, Screen};
use crate::session::Snapshot;
use crate::theme::tokens;
use crate::widgets::{ClickHandler, TextButton, rule};
use gpui::{
    AnyElement, App, ClickEvent, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString, StatefulInteractiveElement as _,
    Styled, Window, div, px,
};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{Account, AccountRow, Catalogue, Mention, SourceRef, Standing, StoredHit};

const WIDTH: f32 = 460.;

pub(super) type JumpHandler = Rc<dyn Fn(Jump, &mut Window, &mut App)>;
/// Show a finding (hit id, value) in the "All traces" list.
pub(super) type FindingHandler = Rc<dyn Fn(i64, String, &mut Window, &mut App)>;

/// What the panel shows, loaded off the UI thread.
#[derive(Clone)]
pub(super) enum Detail {
    /// A resolved account (`account` is `None` until it is loaded).
    Account { row: AccountRow, account: Option<Account>, mention: Option<Mention> },
    /// A bare byte-level sighting and its first places.
    Sighting { row: AccountRow, mention: Option<Mention>, hits: Vec<StoredHit> },
}

impl Detail {
    pub fn row(&self) -> &AccountRow {
        match self {
            Self::Account { row, .. } | Self::Sighting { row, .. } => row,
        }
    }
}

#[derive(IntoElement)]
pub struct AccountDetail {
    detail: Detail,
    snapshot: Snapshot,
    on_jump: JumpHandler,
    on_finding: FindingHandler,
    on_close: ClickHandler,
}

impl AccountDetail {
    pub(super) fn new(
        detail: Detail,
        snapshot: Snapshot,
        on_jump: JumpHandler,
        on_finding: FindingHandler,
        on_close: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    ) -> Self {
        Self { detail, snapshot, on_jump, on_finding, on_close: Rc::new(on_close) }
    }

    fn caption(text: impl Into<SharedString>) -> impl IntoElement {
        let t = tokens();
        div().pt(px(14.)).pb(px(4.)).text_size(t.size_small).text_color(t.text_secondary).child(text.into())
    }

    fn line(text: impl Into<SharedString>) -> gpui::Div {
        let t = tokens();
        div().text_size(t.size_body).text_color(t.text).line_height(px(19.)).whitespace_normal().child(text.into())
    }

    /// One evidence line: caption, text and an optional link.
    fn evidence(caption: String, text: String, button: Option<TextButton>) -> AnyElement {
        let t = tokens();
        h_flex()
            .gap(px(12.))
            .py(px(6.))
            .items_center()
            .border_b_1()
            .border_color(t.row_rule)
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap(px(2.))
                    .child(div().text_size(t.size_small).text_color(t.text_secondary).truncate().child(caption))
                    .child(div().text_size(t.size_body).text_color(t.text).whitespace_normal().child(text)),
            )
            .children(button)
            .into_any_element()
    }

    /// Every trace, strongest kind first.
    fn source_rows(&self, account: &Account) -> Vec<AnyElement> {
        let mut sources: Vec<_> = account.sources().iter().collect();
        sources.sort_by_key(|s| (s.trace, s.at));
        sources
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                let when = s.at.map(|a| a.to_string()).unwrap_or_else(|| "undated".into());
                let caption = format!("{} · {when} · {}", s.trace.label(), self.snapshot.disk_label(s.evidence));
                let button = match &s.origin {
                    SourceRef::Hit(id) => {
                        let (on_finding, id, value) = (self.on_finding.clone(), *id, account.identifier().to_string());
                        Some(TextButton::new(("acc-src", i), "Show finding").on_click(move |_, w, cx| on_finding(id, value.clone(), w, cx)))
                    }
                    SourceRef::Event(_) => s.at.map(|at| {
                        let on_jump = self.on_jump.clone();
                        TextButton::new(("acc-src", i), "Show day").on_click(move |_, w, cx| on_jump(Jump::Day(at), w, cx))
                    }),
                    SourceRef::File(_) => None,
                };
                let text = match &s.origin {
                    SourceRef::File(path) => format!("{} — {path}", s.detail),
                    _ => s.detail.clone(),
                };
                Self::evidence(caption, text, button)
            })
            .collect()
    }

    fn hit_rows(&self, hits: &[StoredHit]) -> Vec<AnyElement> {
        hits.iter()
            .enumerate()
            .map(|(i, h)| {
                let place = h.file_path.clone().unwrap_or_else(|| format!("free space at {}", format::hex_offset(h.hit.offset)));
                let caption = self.snapshot.disk_label(h.evidence);
                let (on_finding, id, value) = (self.on_finding.clone(), h.id, h.hit.value.clone());
                let button = TextButton::new(("acc-hit", i), "Show finding").on_click(move |_, w, cx| on_finding(id, value.clone(), w, cx));
                Self::evidence(caption, place, Some(button))
            })
            .collect()
    }

    fn linked_rows(&self, account: &Account) -> Vec<AnyElement> {
        account
            .linked()
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let (service, identifier) = key.split_once('|').unwrap_or(("", key));
                let service = Catalogue::shared().by_id(service).map_or(service, |e| e.name());
                let on_jump = self.on_jump.clone();
                let jump = Jump::Search { screen: Screen::Accounts, text: identifier.to_string() };
                let button = TextButton::new(("acc-link", i), "Show").on_click(move |_, w, cx| on_jump(jump.clone(), w, cx));
                Self::evidence(service.to_string(), identifier.to_string(), Some(button))
            })
            .collect()
    }

    /// The verdict in a sentence or two.
    fn summary(row: &AccountRow, disks: &str) -> String {
        let seen = match (row.first_seen, row.last_seen) {
            (Some(f), Some(l)) if day(Some(f)) != day(Some(l)) => format!("seen from {} to {}", day(Some(f)), day(Some(l))),
            (Some(f), _) | (_, Some(f)) => format!("seen on {}", day(Some(f))),
            _ => "undated".to_string(),
        };
        let password = if row.secret { " A saved password is available." } else { "" };
        let reasons = reasons_text(&row.reasons, usize::MAX);
        match (row.standing, row.mention_only) {
            (Standing::Used, _) => format!(
                "Used by the owner ({}): {reasons}. {}, on {disks}; strength {:.0}%.{password}",
                row.group.label(),
                capitalise(&seen),
                row.strength * 100.0
            ),
            (Standing::Bulk, true) => format!(
                "Only found in data on {disks}. Every place it was found lists many other addresses too (a dump, a mailing list, an address book)."
            ),
            (_, true) => format!("Only found in data on {disks}, never in use. Found where few other addresses are: worth a look."),
            _ => format!("Only seen, not proven to be the owner's: {reasons}. {}, on {disks}.", capitalise(&seen)),
        }
    }

    fn mention_line(m: &Mention) -> String {
        let crowd = if m.is_bulk() {
            "only in crowded places (dumps, lists)".to_string()
        } else {
            format!("its quietest place holds {}", format::count(m.density, "address", "addresses"))
        };
        format!("The address was found byte-level {} in {}; {crowd}.", format::count(m.hits, "time", "times"), format::count(m.places, "place", "places"))
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
}

impl RenderOnce for AccountDetail {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let row = self.detail.row().clone();
        let close = self.on_close.clone();
        let entry = row.service_id.as_deref().and_then(|id| Catalogue::shared().by_id(id));
        let mut meta = vec![row.service.clone()];
        meta.extend(row.service_kind.clone());
        meta.extend(entry.and_then(|e| e.years()).map(|y| y.to_string()));
        let disks = row.disks.iter().map(|e| self.snapshot.disk_label(*e)).collect::<Vec<_>>().join(", ");
        let notes = entry.map(|e| format!("{}.", e.notes().trim_end_matches('.'))).filter(|n| n.len() > 1);
        let mail = (row.kind == "e-mail").then(|| {
            let (on_jump, jump) = (self.on_jump.clone(), Jump::Search { screen: Screen::Mail, text: row.identifier.clone() });
            TextButton::new("acc-mail", "Show mail").on_click(move |_, w, cx| on_jump(jump.clone(), w, cx))
        });
        let connections = (!row.mention_only).then(|| {
            let (on_jump, jump) = (self.on_jump.clone(), Jump::Connections(ConnectTo::Entity(format!("acct:{}", row.key))));
            TextButton::new("acc-connections", "Connections").on_click(move |_, w, cx| on_jump(jump.clone(), w, cx))
        });
        let mut body = v_flex().gap(px(6.)).child(Self::line(Self::summary(&row, &disks))).children(notes.map(Self::line));
        match &self.detail {
            Detail::Account { account, mention, .. } => {
                body = body.children(mention.as_ref().map(|m| Self::line(Self::mention_line(m)).text_color(t.text_secondary)));
                match account {
                    Some(a) => {
                        let linked = self.linked_rows(a);
                        body = body.child(Self::caption("Evidence")).child(v_flex().children(self.source_rows(a)));
                        if !linked.is_empty() {
                            body = body.child(Self::caption("Same name elsewhere")).child(v_flex().children(linked));
                        }
                    }
                    None => body = body.child(Self::caption("Loading evidence…")),
                }
            }
            Detail::Sighting { mention, hits, .. } => {
                body = body.children(mention.as_ref().map(|m| Self::line(Self::mention_line(m)).text_color(t.text_secondary)));
                let more = mention.as_ref().is_some_and(|m| m.hits > hits.len() as u64);
                body = body.child(Self::caption(if more { "First places found" } else { "Found in" })).child(v_flex().children(self.hit_rows(hits)));
            }
        }
        v_flex()
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .bg(t.raised)
            .border_l_1()
            .border_color(t.rule)
            .child(
                h_flex()
                    .p(px(20.))
                    .pb(px(12.))
                    .justify_between()
                    .items_start()
                    .gap(px(12.))
                    .child(
                        v_flex()
                            .gap(px(4.))
                            .min_w_0()
                            .child(div().font_family(t.font_data).text_size(t.size_heading).text_color(t.emphasis).whitespace_normal().child(row.identifier.clone()))
                            .child(div().text_size(t.size_small).text_color(t.text_secondary).child(meta.join("  ·  "))),
                    )
                    .child(
                        h_flex()
                            .gap(px(8.))
                            .children(connections)
                            .children(mail)
                            .child(TextButton::new("acc-close", "Close").on_click(move |e, w, cx| close(e, w, cx))),
                    ),
            )
            .child(rule())
            .child(div().id("account-detail").flex_1().min_h_0().overflow_y_scroll().px(px(20.)).py(px(12.)).child(body))
    }
}
