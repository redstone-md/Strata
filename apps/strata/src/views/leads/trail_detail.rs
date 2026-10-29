//! Side panel for one wallet trail: the verdict and why, where to look next, then the chain of
//! evidence, each step linked to the day, finding, file or mail it rests on.

use super::detail::{JumpHandler, linked_row, panel_section};
use super::window_text;
use crate::categories;
use crate::nav::{Jump, Screen};
use crate::session::Snapshot;
use crate::theme::tokens;
use crate::widgets::{ClickHandler, TextButton, mono, rule};
use gpui::{App, ClickEvent, InteractiveElement as _, prelude::FluentBuilder as _, IntoElement, ParentElement, RenderOnce, SharedString, StatefulInteractiveElement as _, Styled, Window, div, px};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{Trail, TrailLink, TrailStep};

const WIDTH: f32 = 560.;

#[derive(IntoElement)]
pub struct TrailDetail {
    trail: Trail,
    snapshot: Snapshot,
    on_jump: JumpHandler,
    on_close: ClickHandler,
}

impl TrailDetail {
    pub fn new(trail: Trail, snapshot: Snapshot, on_jump: JumpHandler, on_close: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        Self { trail, snapshot, on_jump, on_close: Rc::new(on_close) }
    }

    /// Where a step's link goes, and the button word for it.
    fn link(step: &TrailStep) -> Option<(&'static str, Jump)> {
        match &step.link {
            TrailLink::Event(_) => step.at.map(|at| ("Show day", Jump::Day(at))),
            TrailLink::Hit { category, value, .. } => Some(("Show finding", Jump::Search { screen: categories::screen(*category), text: value.clone() })),
            TrailLink::File { evidence, volume: Some(volume), path } => {
                let name = path.rsplit(['/', '\\']).next().unwrap_or(path).to_string();
                Some(("Show file", Jump::File { evidence: *evidence, volume: *volume, name }))
            }
            TrailLink::File { volume: None, .. } => None,
            TrailLink::Message { subject, .. } => Some(("Show mail", Jump::Search { screen: Screen::Mail, text: subject.clone() })),
        }
    }

    fn steps(&self) -> Vec<gpui::AnyElement> {
        self.trail
            .steps
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let when = s.at.map_or_else(|| "undated".to_string(), |t| t.to_string());
                let caption = format!("{when} · {} · {}", s.kind.label(), self.snapshot.disk_label(s.evidence));
                linked_row(&self.on_jump, ("trail-step", i), caption, s.text.clone(), false, Self::link(s)).into_any_element()
            })
            .collect()
    }
}

fn paragraph(text: &str) -> impl IntoElement {
    let t = tokens();
    div().text_size(t.size_body).text_color(t.text).line_height(px(19.)).whitespace_normal().child(SharedString::from(text.to_string()))
}

impl RenderOnce for TrailDetail {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let tr = &self.trail;
        let close = self.on_close.clone();
        let mut meta = vec![tr.verdict.fate.label().to_string(), format!("{:.0}% sure", tr.verdict.confidence * 100.0), format!("score {:.0}", tr.score)];
        meta.extend(tr.kind.map(|k| k.label().to_string()));
        meta.extend(Some(window_text(tr.window)).filter(|w| !w.is_empty()));
        let explanation: Vec<_> = tr.verdict.explanation.iter().map(|s| paragraph(s)).collect();
        let hints: Vec<_> = tr.hints.iter().map(|s| paragraph(s)).collect();
        let has_hints = !hints.is_empty();
        let steps = self.steps();
        v_flex()
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .bg(t.raised)
            .border_l_1()
            .border_color(t.rule)
            .child(
                v_flex().p(px(20.)).pb(px(12.)).gap(px(6.)).child(
                    h_flex()
                        .justify_between()
                        .items_start()
                        .gap(px(12.))
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .min_w_0()
                                .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).whitespace_normal().child(tr.name.clone()))
                                .child(mono().text_size(t.size_small).text_color(t.text_secondary).whitespace_normal().child(tr.origin.clone()))
                                .child(div().text_size(t.size_small).text_color(t.text_secondary).child(meta.join("  ·  "))),
                        )
                        .child(TextButton::new("trail-close", "Close").on_click(move |e, w, cx| close(e, w, cx))),
                ),
            )
            .child(rule())
            .child(
                div().id("trail-detail").flex_1().min_h_0().overflow_y_scroll().px(px(20.)).py(px(12.)).child(
                    v_flex()
                        .gap(px(8.))
                        .children(explanation)
                        .when(has_hints, |el| el.child(panel_section("Where to look")).children(hints))
                        .child(panel_section("Chain of evidence"))
                        .child(v_flex().children(steps))
                        .child(div().h(px(8.))),
                ),
            )
    }
}
