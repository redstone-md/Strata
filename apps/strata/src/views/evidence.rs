//! Evidence: add disk images / physical drives, inspect volumes, start analysis.

use crate::format;
use crate::picker::{PickKind, pick_path};
use crate::session::{DiskSummary, Session};
use crate::theme::tokens;
use crate::widgets::{GlassCard, Glyph, Pill, SearchField};
use gpui::{
    AppContext as _, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Subscription,
    Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{Disableable as _, Icon, h_flex, v_flex};

pub struct EvidenceView {
    session: Entity<Session>,
    path: Entity<InputState>,
    message: Option<(bool, SharedString)>,
    _subscriptions: Vec<Subscription>,
}

impl EvidenceView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let path = cx.new(|cx| {
            InputState::new(window, cx).placeholder(r"D:\images\disk.img  ·  .dd / .001 / .rdr  ·  \\.\PhysicalDrive1")
        });
        let subscriptions = vec![
            cx.observe(&session, |_, _, cx| cx.notify()),
            cx.subscribe_in(&path, window, |this, _, event: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = event {
                    this.add(window, cx);
                }
            }),
        ];
        Self { session, path, message: None, _subscriptions: subscriptions }
    }

    fn add(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let location = self.path.read(cx).value().to_string();
        let result = self.session.update(cx, |s, cx| s.add_evidence(&location, cx));
        self.message = Some(match result {
            Ok(()) => {
                self.path.update(cx, |p, cx| p.set_value("", window, cx));
                (false, format!("Added {location}").into())
            }
            Err(e) => (true, e.into()),
        });
        cx.notify();
    }

    fn browse(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let input = self.path.downgrade();
        let window = window.window_handle();
        pick_path(PickKind::File, cx, move |path, cx| {
            let _ = window.update(cx, |_, window, cx| {
                let _ = input.update(cx, |p, cx| p.set_value(path.display().to_string(), window, cx));
            });
        });
    }

    fn add_card(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let message = self.message.clone().map(|(err, text)| {
            div().text_size(t.size_caption).text_color(if err { t.red } else { t.green }).child(text)
        });
        GlassCard::new()
            .title("Add evidence")
            .subtitle("Raw images (.img, .dd, .001…), R-Studio images (.rdr) or a live drive. Evidence is opened read-only.")
            .child(
                h_flex()
                    .gap_3()
                    .child(div().flex_1().child(SearchField::new(&self.path).glyph(Glyph::HardDrive)))
                    .child(
                        Button::new("browse")
                            .icon(Icon::new(Glyph::FolderOpen))
                            .label("Browse…")
                            .ghost()
                            .on_click(cx.listener(|this, _, window, cx| this.browse(window, cx))),
                    )
                    .child(
                        Button::new("add")
                            .icon(Icon::new(Glyph::Plus))
                            .label("Add")
                            .primary()
                            .on_click(cx.listener(|this, _, window, cx| this.add(window, cx))),
                    ),
            )
            .children(message)
    }

    fn disk_card(&self, disk: &DiskSummary, busy: bool) -> impl IntoElement {
        let t = tokens();
        let info = &disk.record.info;
        let id = disk.id();
        let session = self.session.clone();
        let header = |cells: [&'static str; 6]| {
            h_flex()
                .gap_3()
                .text_size(t.size_caption)
                .text_color(t.text_muted)
                .children(cells.into_iter().enumerate().map(|(i, c)| div().w(px(WIDTHS[i])).child(c)))
        };
        let rows = disk.record.volumes.iter().map(|v| {
            let cells = [
                format!("#{}", v.index),
                format!("{:?}", v.fs),
                format!("{:?}", v.origin),
                format::hex_offset(v.range.start()),
                format::bytes(v.range.len()),
                v.label.clone(),
            ];
            h_flex()
                .gap_3()
                .py_1p5()
                .border_t_1()
                .border_color(t.separator)
                .text_sm()
                .text_color(t.text)
                .children(cells.into_iter().enumerate().map(|(i, c)| div().w(px(WIDTHS[i])).truncate().child(c)))
        });
        GlassCard::new()
            .title(info.label.clone())
            .subtitle(format!("{} · {} · {:?} · sector {}", info.location, format::bytes(info.len), info.kind, info.sector_size))
            .action(
                h_flex()
                    .gap_2()
                    .when(disk.scan_complete, |el| el.child(Pill::new("scanned", t.green)))
                    .when(disk.damaged > 0, |el| el.child(Pill::new(format!("{} unreadable", format::bytes(disk.damaged)), t.orange)))
                    .child(
                        Button::new(SharedString::from(format!("analyse-ev-{id}")))
                            .primary()
                            .icon(Icon::new(Glyph::Play))
                            .label(if busy { "Running…" } else { "Analyse" })
                            .disabled(busy)
                            .on_click(move |_, _, cx| session.update(cx, |s, cx| s.analyse(id, cx))),
                    ),
            )
            .child(
                v_flex()
                    .child(header(["Volume", "Filesystem", "Origin", "Offset", "Size", "Label"]))
                    .children(rows)
                    .when(disk.record.volumes.is_empty(), |el| {
                        el.child(div().py_2().text_sm().text_color(t.text_dim).child("No volumes found"))
                    }),
            )
    }
}

const WIDTHS: [f32; 6] = [70., 100., 110., 130., 100., 240.];

impl Render for EvidenceView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let snapshot = self.session.read(cx).snapshot().clone();
        let cards: Vec<_> = snapshot
            .disks
            .iter()
            .map(|d| self.disk_card(d, snapshot.active_jobs().any(|j| j.evidence == d.id())))
            .collect();
        v_flex().gap(t.gap).child(self.add_card(cx)).children(cards)
    }
}
