//! Side panel for one account: the service as the catalogue knows it, when the account was
//! seen, every trace naming it, and the same name on other services.

use super::{day, years};
use crate::nav::{Jump, Screen};
use crate::session::Snapshot;
use crate::theme::tokens;
use crate::widgets::{ClickHandler, TextButton, rule};
use gpui::{App, ClickEvent, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString, StatefulInteractiveElement as _, Styled, Window, div, prelude::FluentBuilder as _, px};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{Account, Catalogue, IdentifierKind, SourceRef};

const WIDTH: f32 = 460.;

type JumpHandler = Rc<dyn Fn(Jump, &mut Window, &mut App)>;

#[derive(IntoElement)]
pub struct AccountDetail {
    account: Account,
    snapshot: Snapshot,
    on_jump: JumpHandler,
    on_close: ClickHandler,
}

impl AccountDetail {
    pub fn new(account: Account, snapshot: Snapshot, on_jump: JumpHandler, on_close: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        Self { account, snapshot, on_jump, on_close: Rc::new(on_close) }
    }

    fn caption(text: impl Into<SharedString>) -> impl IntoElement {
        let t = tokens();
        div().pt(px(14.)).pb(px(4.)).text_size(t.size_small).text_color(t.text_secondary).child(text.into())
    }

    fn line(text: impl Into<SharedString>) -> gpui::Div {
        let t = tokens();
        div().text_size(t.size_body).text_color(t.text).line_height(px(19.)).whitespace_normal().child(text.into())
    }

    fn source_rows(&self) -> Vec<gpui::AnyElement> {
        let t = tokens();
        self.account
            .sources()
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let when = s.at.map(|a| a.to_string()).unwrap_or_else(|| "undated".into());
                let caption = format!("{when} · {}", self.snapshot.disk_label(s.evidence));
                let button = match (&s.origin, s.at) {
                    (SourceRef::Event(_), Some(at)) => {
                        let on_jump = self.on_jump.clone();
                        Some(TextButton::new(("acc-src", i), "Show day").on_click(move |_, w, cx| on_jump(Jump::Day(at), w, cx)))
                    }
                    _ => None,
                };
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
                            .child(div().text_size(t.size_small).text_color(t.text_secondary).child(caption))
                            .child(div().text_size(t.size_body).text_color(t.text).truncate().child(s.detail.clone())),
                    )
                    .children(button)
                    .into_any_element()
            })
            .collect()
    }

    fn linked_rows(&self) -> Vec<gpui::AnyElement> {
        let t = tokens();
        self.account
            .linked()
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let (service, identifier) = key.split_once('|').unwrap_or(("", key));
                let service = Catalogue::shared().by_id(service).map_or(service, |e| e.name());
                let on_jump = self.on_jump.clone();
                let jump = Jump::Search { screen: Screen::Accounts, text: identifier.to_string() };
                h_flex()
                    .gap(px(12.))
                    .py(px(6.))
                    .items_center()
                    .border_b_1()
                    .border_color(t.row_rule)
                    .child(div().flex_1().min_w_0().text_size(t.size_body).text_color(t.text).truncate().child(format!("{identifier} on {service}")))
                    .child(TextButton::new(("acc-link", i), "Show").on_click(move |_, w, cx| on_jump(jump.clone(), w, cx)))
                    .into_any_element()
            })
            .collect()
    }
}

impl RenderOnce for AccountDetail {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let a = &self.account;
        let close = self.on_close.clone();
        let entry = a.service_id().and_then(|id| Catalogue::shared().by_id(id));
        let mut meta = vec![a.service().to_string()];
        meta.extend(a.service_kind().map(|k| k.label().to_string()));
        meta.extend(Some(years(a)).filter(|y| !y.is_empty()));
        let seen = match (a.first_seen(), a.last_seen()) {
            (Some(f), Some(l)) if day(Some(f)) != day(Some(l)) => format!("seen from {} to {}", day(Some(f)), day(Some(l))),
            (Some(f), _) | (_, Some(f)) => format!("seen on {}", day(Some(f))),
            _ => "seen without a date".to_string(),
        };
        let disks: Vec<String> = a.disks().iter().map(|e| self.snapshot.disk_label(*e)).collect();
        let kind = a.kind().label();
        let summary = format!(
            "{}{} {seen} in {} on {}; confidence {:.0}%.",
            kind.get(..1).unwrap_or_default().to_uppercase(),
            kind.get(1..).unwrap_or_default(),
            if a.sources().len() == 1 { "1 trace".to_string() } else { format!("{} traces", a.sources().len()) },
            disks.join(", "),
            a.confidence() * 100.0
        );
        let notes = entry.map(|e| format!("{}.", e.notes().trim_end_matches('.'))).filter(|n| n.len() > 1);
        let domains = entry.map(|e| e.domains().join(", ")).filter(|d| !d.is_empty());
        let linked = self.linked_rows();
        let mail = (a.kind() == IdentifierKind::Email).then(|| {
            let (on_jump, jump) = (self.on_jump.clone(), Jump::Search { screen: Screen::Mail, text: a.identifier().to_string() });
            TextButton::new("acc-mail", "Show mail").on_click(move |_, w, cx| on_jump(jump.clone(), w, cx))
        });
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
                            .child(div().font_family(t.font_data).text_size(t.size_heading).text_color(t.emphasis).whitespace_normal().child(a.identifier().to_string()))
                            .child(div().text_size(t.size_small).text_color(t.text_secondary).child(meta.join("  ·  "))),
                    )
                    .child(
                        h_flex()
                            .gap(px(8.))
                            .children(mail)
                            .child(TextButton::new("acc-close", "Close").on_click(move |e, w, cx| close(e, w, cx))),
                    ),
            )
            .child(rule())
            .child(
                div().id("account-detail").flex_1().min_h_0().overflow_y_scroll().px(px(20.)).py(px(12.)).child(
                    v_flex()
                        .gap(px(6.))
                        .child(Self::line(summary))
                        .children(notes.map(Self::line))
                        .children(domains.map(|d| Self::line(format!("Domains: {d}")).text_color(t.text_secondary)))
                        .child(Self::caption("Seen in"))
                        .child(v_flex().children(self.source_rows()))
                        .when_some((!linked.is_empty()).then_some(linked), |el, rows| el.child(Self::caption("Same name elsewhere")).child(v_flex().children(rows))),
                ),
            )
    }
}
