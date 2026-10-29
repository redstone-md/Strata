//! Side panel for one node of the map: what it is and why it ranks, where to open it, and every
//! link with its reason and the evidence behind it.

use crate::nav::{Jump, Screen};
use crate::session::Snapshot;
use crate::theme::tokens;
use crate::widgets::{ClickHandler, TextButton, rule};
use gpui::{App, ClickEvent, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString, StatefulInteractiveElement as _, Styled, Window, div, px};
use gpui_component::{h_flex, v_flex};
use std::rc::Rc;
use strata_workbench::{Link, Node, NodeDetail, NodeKey, NodeKind};

const WIDTH: f32 = 440.;
/// Evidence lines shown under each link.
const EVIDENCE_LINES: usize = 3;

type JumpHandler = Rc<dyn Fn(Jump, &mut Window, &mut App)>;
type CentreHandler = Rc<dyn Fn(NodeKey, &mut Window, &mut App)>;

#[derive(IntoElement)]
pub struct NodePanel {
    detail: NodeDetail,
    centred: bool,
    snapshot: Snapshot,
    on_jump: JumpHandler,
    on_centre: CentreHandler,
    on_close: ClickHandler,
}

fn date(t: strata_workbench::Timestamp) -> String {
    t.to_string().chars().take(10).collect()
}

fn day(node: &Node) -> String {
    match (node.first_seen().map(date), node.last_seen().map(date)) {
        (Some(f), Some(l)) if f != l => format!("{f} to {l}"),
        (Some(f), _) => format!("seen {f}"),
        _ => String::new(),
    }
}

/// Where the node lives elsewhere in the app.
fn opens(node: &Node) -> Vec<(&'static str, Jump)> {
    let label = node.label().to_string();
    let search = |screen: Screen, text: String| Jump::Search { screen, text };
    let mut out = Vec::new();
    match node.kind() {
        NodeKind::Secret | NodeKind::Address => out.push(("Open finding", search(Screen::Wallets, label))),
        NodeKind::Identity => {
            out.push(("Open finding", search(Screen::Accounts, label.clone())));
            if label.contains('@') {
                out.push(("Show mail", search(Screen::Mail, label)));
            }
        }
        NodeKind::Account => {
            let identifier = node.key().as_str().split_once('|').map_or(label.clone(), |(_, id)| id.to_string());
            out.push(("Show account", search(Screen::Accounts, identifier)));
        }
        NodeKind::File => out.push(("Show findings", search(Screen::Wallets, node.caption().to_string()))),
        NodeKind::Message => out.push(("Show mail", search(Screen::Mail, label))),
        NodeKind::Lead => out.push(("Show lead", search(Screen::Leads, label))),
        NodeKind::Service | NodeKind::Disk => {}
    }
    if let Some(at) = node.first_seen() {
        out.push(("Open in Timeline", Jump::Day(at)));
    }
    out
}

impl NodePanel {
    pub fn new(detail: NodeDetail, centred: bool, snapshot: Snapshot, on_jump: JumpHandler, on_centre: CentreHandler, on_close: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static) -> Self {
        Self { detail, centred, snapshot, on_jump, on_centre, on_close: Rc::new(on_close) }
    }

    fn caption(text: impl Into<SharedString>) -> impl IntoElement {
        let t = tokens();
        div().pt(px(14.)).pb(px(4.)).text_size(t.size_small).text_color(t.text_secondary).child(text.into())
    }

    fn line(text: impl Into<SharedString>) -> gpui::Div {
        let t = tokens();
        div().text_size(t.size_body).text_color(t.text).line_height(px(19.)).whitespace_normal().child(text.into())
    }

    fn link_row(&self, i: usize, link: &Link) -> impl IntoElement {
        let t = tokens();
        let times = if link.count > 1 { format!(" · {}×", link.count) } else { String::new() };
        let caption = format!("{} · {}{times}", link.phrase(), link.other.kind().label());
        let on_centre = self.on_centre.clone();
        let key = link.other.key().clone();
        let more = (link.count as usize).saturating_sub(link.evidence.len().min(EVIDENCE_LINES));
        let evidence = link.evidence.iter().take(EVIDENCE_LINES).map(|e| div().truncate().child(e.describe()));
        let value = div().text_size(t.size_body).text_color(t.text).truncate().child(link.other.label().to_string());
        let value = if matches!(link.other.kind(), NodeKind::Lead | NodeKind::Message | NodeKind::Disk | NodeKind::Service) { value } else { value.font_family(t.font_data) };
        h_flex()
            .gap(px(12.))
            .py(px(6.))
            .items_start()
            .border_b_1()
            .border_color(t.row_rule)
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap(px(2.))
                    .child(div().text_size(t.size_small).text_color(t.text_secondary).truncate().child(caption))
                    .child(value)
                    .child(
                        v_flex()
                            .text_size(t.size_small)
                            .text_color(t.text_secondary)
                            .children(evidence)
                            .children((more > 0 && !link.evidence.is_empty()).then(|| format!("and {more} more"))),
                    ),
            )
            .child(TextButton::new(("node-link", i), "Center").on_click(move |_, w, cx| on_centre(key.clone(), w, cx)))
    }
}

impl RenderOnce for NodePanel {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let t = tokens();
        let n = &self.detail.node;
        let close = self.on_close.clone();
        let mut meta = vec![n.caption().to_string(), format!("score {:.0}", n.score())];
        meta.extend(Some(day(n)).filter(|d| !d.is_empty()));
        let disks: Vec<String> = n.disks().iter().map(|d| self.snapshot.disk_label(*d)).collect();
        if !disks.is_empty() {
            meta.push(format!("on {}", disks.join(", ")));
        }
        let mut actions: Vec<gpui::AnyElement> = Vec::new();
        if !self.centred {
            let (on_centre, key) = (self.on_centre.clone(), n.key().clone());
            actions.push(TextButton::new("node-centre", "Center here").strong().on_click(move |_, w, cx| on_centre(key.clone(), w, cx)).into_any_element());
        }
        for (i, (label, jump)) in opens(n).into_iter().enumerate() {
            let on_jump = self.on_jump.clone();
            actions.push(TextButton::new(("node-open", i), label).on_click(move |_, w, cx| on_jump(jump.clone(), w, cx)).into_any_element());
        }
        let links: Vec<gpui::AnyElement> = self.detail.links.iter().enumerate().map(|(i, l)| self.link_row(i, l).into_any_element()).collect();
        let header = if matches!(n.kind(), NodeKind::Lead | NodeKind::Message | NodeKind::Disk | NodeKind::Service) { t.font_ui } else { t.font_data };
        v_flex()
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .bg(t.raised)
            .border_l_1()
            .border_color(t.rule)
            .child(
                v_flex().p(px(20.)).pb(px(12.)).gap(px(10.)).child(
                    h_flex()
                        .justify_between()
                        .items_start()
                        .gap(px(12.))
                        .child(
                            v_flex()
                                .gap(px(4.))
                                .min_w_0()
                                .child(div().font_family(header).text_size(t.size_heading).text_color(t.emphasis).whitespace_normal().child(n.label().to_string()))
                                .child(div().text_size(t.size_small).text_color(t.text_secondary).whitespace_normal().child(meta.join("  ·  "))),
                        )
                        .child(TextButton::new("node-close", "Close").on_click(move |e, w, cx| close(e, w, cx))),
                )
                .child(h_flex().flex_wrap().gap(px(8.)).children(actions)),
            )
            .child(rule())
            .child(
                div().id("node-detail").flex_1().min_h_0().overflow_y_scroll().px(px(20.)).py(px(12.)).child(
                    v_flex()
                        .gap(px(4.))
                        .children(n.why().iter().map(|w| Self::line(w.clone())))
                        .child(Self::caption(match self.detail.links.len() + self.detail.more_links {
                            1 => "1 link".to_string(),
                            k => format!("{k} links"),
                        }))
                        .child(v_flex().children(links))
                        .children((self.detail.more_links > 0).then(|| Self::line(format!("{} more not listed", self.detail.more_links)).text_color(t.text_secondary)))
                        .child(div().h(px(8.))),
                ),
            )
    }
}
