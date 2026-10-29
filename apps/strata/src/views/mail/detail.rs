//! Side panel for one message: who wrote to whom and when, the body as text, attachments
//! with Export, every place the message was found, damage notes and all headers.

use super::delegate::date;
use crate::theme::tokens;
use crate::widgets::{Badge, ClickHandler, TextButton, mono, rule};
use gpui::{
    App, ClickEvent, ClipboardItem, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement as _, Styled, Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{MessageState, StoredMessage, join_parties as join};

const WIDTH: f32 = 560.;
/// Body text rendered in the panel; the rest is in the exported message.
const SHOWN_BODY: usize = 200 * 1024;

/// Called with the attachment index to export.
type AttachmentHandler = Rc<dyn Fn(usize, &mut Window, &mut App)>;

#[derive(IntoElement)]
pub struct MailDetail {
    stored: StoredMessage,
    disk: String,
    note: Option<SharedString>,
    all_headers: bool,
    on_close: ClickHandler,
    on_toggle_headers: ClickHandler,
    on_export: ClickHandler,
    on_attachment: AttachmentHandler,
}

impl MailDetail {
    pub fn new(stored: StoredMessage, disk: String, note: Option<SharedString>, all_headers: bool) -> Self {
        let noop: ClickHandler = Rc::new(|_, _, _| {});
        Self {
            stored,
            disk,
            note,
            all_headers,
            on_close: noop.clone(),
            on_toggle_headers: noop.clone(),
            on_export: noop,
            on_attachment: Rc::new(|_, _, _| {}),
        }
    }

    pub fn on_close(mut self, f: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.on_close = Rc::new(f);
        self
    }

    pub fn on_toggle_headers(mut self, f: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.on_toggle_headers = Rc::new(f);
        self
    }

    pub fn on_export(mut self, f: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        self.on_export = Rc::new(f);
        self
    }

    pub fn on_attachment(mut self, f: impl Fn(usize, &mut Window, &mut App) + 'static) -> Self {
        self.on_attachment = Rc::new(f);
        self
    }

    fn caption(text: impl Into<SharedString>) -> impl IntoElement {
        let t = tokens();
        div().pt(px(16.)).pb(px(6.)).text_size(t.size_small).text_color(t.text_secondary).child(text.into())
    }

    /// `label  value` with the value wrapping in the data face.
    fn field(label: &str, value: String) -> impl IntoElement {
        let t = tokens();
        h_flex()
            .items_start()
            .gap(px(8.))
            .py(px(2.))
            .child(div().w(px(84.)).flex_shrink_0().text_size(t.size_body).text_color(t.text_secondary).child(label.to_string()))
            .child(mono().flex_1().min_w_0().text_size(t.size_body).text_color(t.text).whitespace_normal().child(value))
    }

    fn summary(&self) -> Vec<gpui::AnyElement> {
        let e = &self.stored.message.envelope;
        let mut rows = vec![
            Self::field("From", join(&e.from)),
            Self::field("To", join(&e.to)),
        ];
        if !e.cc.is_empty() {
            rows.push(Self::field("Cc", join(&e.cc)));
        }
        rows.push(Self::field("Date", e.date.map_or_else(|| "no date".into(), |d| format!("{d} UTC"))));
        rows.extend(e.message_id.as_ref().map(|id| Self::field("Message-ID", id.clone())));
        rows.push(Self::field("Disk", self.disk.clone()));
        rows.into_iter().map(IntoElement::into_any_element).collect()
    }

    fn attachments(&self) -> Vec<gpui::AnyElement> {
        let t = tokens();
        self.stored
            .message
            .attachments
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let handler = self.on_attachment.clone();
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
                            .child(mono().text_size(t.size_body).text_color(t.text).truncate().child(a.name.clone()))
                            .child(div().text_size(t.size_small).text_color(t.text_secondary).child(format!("{} · {}", a.mime, crate::format::bytes(a.size)))),
                    )
                    .child(TextButton::new(("mail-att", i), "Export…").on_click(move |_, w, cx| handler(i, w, cx)))
                    .into_any_element()
            })
            .collect()
    }

    fn places(&self) -> Vec<gpui::AnyElement> {
        let t = tokens();
        let row = &self.stored.row;
        std::iter::once(&row.location)
            .chain(&self.stored.places)
            .map(|p| {
                h_flex()
                    .gap(px(8.))
                    .py(px(3.))
                    .child(mono().flex_1().min_w_0().text_size(t.size_body).text_color(t.text).whitespace_normal().child(p.describe()))
                    .child(match p.state {
                        MessageState::Live => Badge::outline("live"),
                        state => Badge::outline(state.name()),
                    })
                    .into_any_element()
            })
            .collect()
    }

    fn headers(&self) -> Vec<gpui::AnyElement> {
        self.stored.message.headers.iter().map(|(n, v)| Self::field(n, v.clone()).into_any_element()).collect()
    }
}

impl RenderOnce for MailDetail {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let m = &self.stored.message;
        let subject = if m.envelope.subject.is_empty() { "(no subject)".to_string() } else { m.envelope.subject.clone() };
        let state = self.stored.row.location.state;
        let caption = format!("{} · {}{}", date(&self.stored.row), state.name(), if m.body_from_html { " · text of an HTML body" } else { "" });
        let body: String = m.body.chars().take(SHOWN_BODY).collect();
        let cut = body.len() < m.body.len();
        let (copy, close, export, toggle) = (m.body.clone(), self.on_close.clone(), self.on_export.clone(), self.on_toggle_headers.clone());
        let notes: Vec<_> = m.notes.iter().map(|n| div().text_size(t.size_body).text_color(t.text).whitespace_normal().child(n.clone())).collect();
        let headers = if self.all_headers { self.headers() } else { Vec::new() };
        v_flex()
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .bg(t.raised)
            .border_l_1()
            .border_color(t.rule)
            .child(
                v_flex()
                    .p(px(20.))
                    .pb(px(12.))
                    .gap(px(10.))
                    .child(
                        h_flex()
                            .justify_between()
                            .items_start()
                            .gap(px(12.))
                            .child(
                                v_flex()
                                    .gap(px(2.))
                                    .min_w_0()
                                    .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).whitespace_normal().child(subject))
                                    .child(div().text_size(t.size_small).text_color(t.text_secondary).child(caption)),
                            )
                            .child(TextButton::new("mail-close", "Close").on_click(move |e, w, cx| close(e, w, cx))),
                    )
                    .child(
                        h_flex()
                            .gap(px(8.))
                            .child(TextButton::new("mail-copy", "Copy text").on_click(move |_, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()))))
                            .child(TextButton::new("mail-export", "Export message…").on_click(move |e, w, cx| export(e, w, cx))),
                    )
                    .children(self.note.clone().map(|n| div().text_size(t.size_body).text_color(t.text).whitespace_normal().child(n))),
            )
            .child(rule())
            .child(
                div().id("mail-detail").flex_1().min_h_0().overflow_y_scroll().px(px(20.)).py(px(8.)).child(
                    v_flex()
                        .children(self.summary())
                        .child(Self::caption("Message"))
                        .child(
                            div()
                                .text_size(t.size_body)
                                .line_height(px(19.))
                                .text_color(t.text)
                                .whitespace_normal()
                                .child(if body.trim().is_empty() { "(no text)".to_string() } else { body }),
                        )
                        .when(cut, |el| el.child(div().pt(px(6.)).text_size(t.size_small).text_color(t.text_secondary).child("The text goes on; export the message to read all of it.")))
                        .when(!m.attachments.is_empty(), |el| el.child(Self::caption("Attachments")).child(v_flex().children(self.attachments())))
                        .child(Self::caption("Found at"))
                        .child(v_flex().children(self.places()))
                        .when(!notes.is_empty(), |el| el.child(Self::caption("Damage")).children(notes))
                        .child(
                            h_flex()
                                .pt(px(16.))
                                .pb(px(6.))
                                .gap(px(8.))
                                .child(div().text_size(t.size_small).text_color(t.text_secondary).child(format!("{} headers", m.headers.len())))
                                .child(TextButton::new("mail-headers", if self.all_headers { "Hide" } else { "Show" }).on_click(move |e, w, cx| toggle(e, w, cx))),
                        )
                        .children(headers),
                ),
            )
    }
}
