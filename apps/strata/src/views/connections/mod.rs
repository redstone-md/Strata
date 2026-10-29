//! Connections: the map of who owns what. Opens on the likely owner (or the most valuable
//! entity), two steps out; every view is cut from the case's connection graph and laid out on
//! a background thread. Click a node for its links and evidence, double-click to centre on it,
//! filter kinds with the legend, and search from the command bar (Enter centres on the match).

mod detail;
mod filter;
mod look;
mod map;
mod paint;

use crate::format;
use crate::nav::{ConnectTo, Jump};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{Choice, TextButton, loading_edge, quiet};
use detail::NodePanel;
use filter::KindFilter;
use gpui::{
    Context, Entity, EventEmitter, IntoElement, ParentElement, Render, Styled, Subscription, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::{h_flex, v_flex};
use map::{MapModel, MapState, Marks};
use std::rc::Rc;
use strata_workbench::{Layout, NodeDetail, NodeKey, NodeKind, ViewScope, Workbench};

/// Most nodes on the map at once.
const LIMIT: usize = 90;

/// What the map is centred on.
#[derive(Debug, Clone, PartialEq)]
enum Centre {
    /// The likely owner, else the most valuable entity.
    Owner,
    /// The best-ranked entities of the whole case.
    Overview,
    On(ConnectTo),
}

pub struct ConnectionsView {
    session: Entity<Session>,
    centre: Centre,
    history: Vec<Centre>,
    depth: u32,
    hidden: Vec<NodeKind>,
    model: Option<Rc<MapModel>>,
    /// Nodes per kind in the whole graph.
    totals: Vec<(NodeKind, usize)>,
    state: Rc<MapState>,
    selected: Option<usize>,
    detail: Option<NodeDetail>,
    search: String,
    matches: Vec<usize>,
    loading: bool,
    /// Bumped per load; a slower earlier load that lands late is dropped.
    loads: u64,
    started: bool,
    note: Option<String>,
    generation: u64,
    was_active: bool,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<Jump> for ConnectionsView {}

impl ConnectionsView {
    pub fn new(session: Entity<Session>, cx: &mut Context<Self>) -> Self {
        let subscriptions = vec![cx.observe(&session, |this, _, cx| this.on_session_changed(cx))];
        let generation = session.read(cx).generation();
        Self {
            session,
            centre: Centre::Owner,
            history: Vec::new(),
            depth: 2,
            hidden: Vec::new(),
            model: None,
            totals: Vec::new(),
            state: Rc::new(MapState::default()),
            selected: None,
            detail: None,
            search: String::new(),
            matches: Vec::new(),
            loading: false,
            loads: 0,
            started: false,
            note: None,
            generation,
            was_active: false,
            _subscriptions: subscriptions,
        }
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let active = session.snapshot().active_jobs().next().is_some();
        let switched = session.generation() != self.generation;
        if switched {
            self.generation = session.generation();
            self.centre = Centre::Owner;
            self.history.clear();
        }
        if self.started && (switched || (self.was_active && !active)) {
            if !switched {
                // Jobs ended: whatever they added belongs on the map now.
                session.workbench().refresh_connections();
            }
            self.reload(cx);
        }
        self.was_active = active;
    }

    /// Centre on an entity another screen links to.
    pub fn show(&mut self, to: ConnectTo, cx: &mut Context<Self>) {
        self.go(Centre::On(to), cx);
    }

    fn go(&mut self, centre: Centre, cx: &mut Context<Self>) {
        if centre != self.centre {
            self.history.push(std::mem::replace(&mut self.centre, centre));
        }
        self.reload(cx);
    }

    fn back(&mut self, cx: &mut Context<Self>) {
        if let Some(previous) = self.history.pop() {
            self.centre = previous;
            self.reload(cx);
        }
    }

    /// Mark the nodes on the map whose value contains the command-bar text.
    pub fn set_search(&mut self, text: &str, cx: &mut Context<Self>) {
        self.search = text.trim().to_string();
        self.mark_matches();
        cx.notify();
    }

    /// Enter in the command bar: centre on the best match in the whole graph.
    pub fn centre_on_search(&mut self, cx: &mut Context<Self>) {
        if !self.search.is_empty() {
            self.go(Centre::On(ConnectTo::Entity(self.search.clone())), cx);
        }
    }

    fn mark_matches(&mut self) {
        let needle = self.search.to_lowercase();
        self.matches = match (&self.model, needle.is_empty()) {
            (Some(m), false) => m.view.nodes.iter().enumerate().filter(|(_, n)| n.node.label().to_lowercase().contains(&needle)).map(|(i, _)| i).collect(),
            _ => Vec::new(),
        };
    }

    fn scope(&self) -> ViewScope {
        let kinds = if self.hidden.is_empty() { Vec::new() } else { NodeKind::ALL.into_iter().filter(|k| !self.hidden.contains(k)).collect() };
        ViewScope::new(self.depth, LIMIT).kinds(kinds)
    }

    /// Cut the view for the current centre out of the graph (built or reused by the workbench)
    /// and lay it out, all off the UI thread.
    fn reload(&mut self, cx: &mut Context<Self>) {
        self.started = true;
        self.loading = true;
        self.loads += 1;
        let ticket = self.loads;
        let (wb, centre, scope) = (self.session.read(cx).workbench().clone(), self.centre.clone(), self.scope());
        cx.spawn(async move |this, cx| {
            let result = cx.background_executor().spawn(async move { load(&wb, &centre, &scope) }).await;
            let _ = this.update(cx, |v, cx| {
                if v.loads != ticket {
                    return;
                }
                v.loading = false;
                match result {
                    Ok((Some(model), totals)) => {
                        v.model = Some(Rc::new(model));
                        v.totals = totals;
                        v.note = None;
                        v.selected = None;
                        v.detail = None;
                        v.state.hovered.set(None);
                        v.state.fit.set(true);
                        v.mark_matches();
                    }
                    Ok((None, totals)) => {
                        v.totals = totals;
                        v.note = Some(match &v.centre {
                            Centre::On(ConnectTo::Entity(t)) => format!("Nothing on the map matches \u{201c}{t}\u{201d}"),
                            Centre::On(ConnectTo::Finding { value, .. }) => format!("The finding {} is not on the map", format::middle(value, 40)),
                            _ => "Nothing to map yet".to_string(),
                        });
                    }
                    Err(e) => v.note = Some(format!("Cannot build the map: {e}")),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn select(&mut self, index: Option<usize>, centre: bool, cx: &mut Context<Self>) {
        let Some(key) = index.and_then(|i| self.model.as_ref()?.view.nodes.get(i)).map(|n| n.node.key().clone()) else {
            self.selected = None;
            self.detail = None;
            cx.notify();
            return;
        };
        if centre {
            self.go(Centre::On(ConnectTo::Entity(key.to_string())), cx);
            return;
        }
        self.selected = index;
        let wb = self.session.read(cx).workbench().clone();
        cx.spawn(async move |this, cx| {
            let detail = cx.background_executor().spawn(async move { wb.connection_detail(key.as_str()) }).await;
            let _ = this.update(cx, |v, cx| {
                let current = v.selected.and_then(|i| v.model.as_ref()?.view.nodes.get(i)).map(|n| n.node.key().clone());
                if let Ok(Some(d)) = detail
                    && Some(d.node.key()) == current.as_ref()
                {
                    v.detail = Some(d);
                    cx.notify();
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn toggle_kind(&mut self, kind: NodeKind, cx: &mut Context<Self>) {
        if let Some(i) = self.hidden.iter().position(|k| *k == kind) {
            self.hidden.remove(i);
        } else if self.hidden.len() + 1 < NodeKind::ALL.len() {
            self.hidden.push(kind);
        }
        self.reload(cx);
    }

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let total: usize = self.totals.iter().map(|(_, n)| n).sum();
        let summary = match &self.model {
            Some(m) => {
                let shown = format!("{} of {}", m.view.nodes.len(), format::count(total as u64, "entity", "entities"));
                if m.view.left_out > 0 { format!("{shown}, {} more nearby", m.view.left_out) } else { shown }
            }
            None => String::new(),
        };
        // The loading line animates every frame, which keeps this step and its time current.
        let note = if self.loading {
            Some(match self.session.read(cx).workbench().connections_step() {
                Some((step, took)) if took.as_secs() >= 1 => format!("Building the map: {step}, {} s", took.as_secs()),
                Some((step, _)) => format!("Building the map: {step}"),
                None => "Building the map…".to_string(),
            })
        } else {
            self.note.clone()
        };
        let ego = self.centre != Centre::Overview;
        let this = cx.entity().downgrade();
        let depth = Choice::new("conn-depth", vec!["1 step".into(), "2 steps".into(), "3 steps".into()], self.depth as usize - 1, move |i, _, cx| {
            let _ = this.update(cx, |v, cx| {
                v.depth = i as u32 + 1;
                v.reload(cx);
            });
        });
        let button = |id: &'static str, label: &'static str, on: bool| if on { TextButton::new(id, label).strong() } else { TextButton::new(id, label) };
        h_flex()
            .h(px(32.))
            .gap(px(16.))
            .items_center()
            .text_size(t.size_body)
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child("Connections"))
            .child(div().text_color(t.text_secondary).child(summary))
            .children(note.map(|n| quiet().child(n)))
            .child(div().flex_1())
            .when(ego, |el| el.child(depth))
            .when(!self.history.is_empty(), |el| el.child(TextButton::new("conn-back", "Back").on_click(cx.listener(|v, _, _, cx| v.back(cx)))))
            .child(button("conn-owner", "Owner", self.centre == Centre::Owner).on_click(cx.listener(|v, _, _, cx| v.go(Centre::Owner, cx))))
            .child(button("conn-overview", "Overview", !ego).on_click(cx.listener(|v, _, _, cx| v.go(Centre::Overview, cx))))
    }

    /// The line under the map: the hovered node, or how to work the map.
    fn status_line(&self) -> impl IntoElement {
        let t = tokens();
        let line = h_flex().h(px(22.)).gap(px(16.)).items_center().text_size(t.size_small).text_color(t.text_secondary);
        let hovered = self.state.hovered.get().and_then(|i| self.model.as_ref()?.view.nodes.get(i));
        match hovered {
            Some(n) => line
                .child(div().text_color(t.text).child(n.node.caption().to_string()))
                .child(div().font_family(t.font_data).text_color(t.emphasis).truncate().child(n.node.label().to_string()))
                .child(format!("score {:.0}", n.node.score()))
                .children((n.more > 0).then(|| format!("{} more links", n.more))),
            None => line.child("Drag to move, scroll to zoom, click a node for its links, double-click to center on it"),
        }
    }
}

type Loaded = (Option<MapModel>, Vec<(NodeKind, usize)>);

/// The view for `centre`, laid out (runs on a background thread).
fn load(wb: &Workbench, centre: &Centre, scope: &ViewScope) -> strata_workbench::Result<Loaded> {
    let graph = wb.connections()?;
    let key: Option<NodeKey> = match centre {
        Centre::Owner => graph.default_centre().map(|n| n.key().clone()),
        Centre::Overview => None,
        Centre::On(ConnectTo::Entity(text)) => graph.resolve(text).map(|n| n.key().clone()),
        Centre::On(ConnectTo::Finding { hit, value }) => wb.connection_of_finding(*hit, value)?,
    };
    let view = match (centre, key) {
        (Centre::Overview, _) => Some(graph.overview(scope)).filter(|v| !v.nodes.is_empty()),
        (_, Some(key)) => graph.around(&key, scope),
        (_, None) => None,
    };
    Ok((view.map(|v| MapModel::new(v.clone(), Layout::compute(&v))), graph.counts()))
}

impl Render for ConnectionsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        if !self.started {
            self.reload(cx);
        }
        let this = cx.entity().downgrade();
        let filter = KindFilter::new(self.hidden.clone(), self.model.as_ref().map(|m| shown(m)).unwrap_or_default(), move |kind, _, cx| {
            let _ = this.update(cx, |v, cx| v.toggle_kind(kind, cx));
        });
        let body = match &self.model {
            Some(model) => {
                let this = cx.entity().downgrade();
                let pick: map::Pick = Rc::new(move |i, double, _, cx| {
                    let _ = this.update(cx, |v, cx| v.select(i, double, cx));
                });
                let marks = Rc::new(Marks { selected: self.selected, matches: self.matches.clone() });
                map::map(model.clone(), self.state.clone(), marks, pick).into_any_element()
            }
            None if self.loading => div().into_any_element(),
            None => div()
                .p(px(24.))
                .child(quiet().child("No connections yet. Keys, accounts, mail and leads appear here once analysis has found them."))
                .into_any_element(),
        };
        let panel = self.detail.clone().map(|d| {
            let centred = self.model.as_ref().and_then(|m| m.view.centre).and_then(|c| self.model.as_ref()?.view.nodes.get(c)).is_some_and(|c| c.node.key() == d.node.key());
            let jump_to = cx.entity().downgrade();
            let on_jump = Rc::new(move |jump: Jump, _: &mut Window, cx: &mut gpui::App| {
                let _ = jump_to.update(cx, |_, cx| cx.emit(jump));
            });
            let centre_to = cx.entity().downgrade();
            let on_centre = Rc::new(move |key: NodeKey, _: &mut Window, cx: &mut gpui::App| {
                let _ = centre_to.update(cx, |v, cx| v.go(Centre::On(ConnectTo::Entity(key.to_string())), cx));
            });
            let close_to = cx.entity().downgrade();
            NodePanel::new(d, centred, self.session.read(cx).snapshot().clone(), on_jump, on_centre, move |_, _, cx| {
                let _ = close_to.update(cx, |v, cx| v.select(None, false, cx));
            })
        });
        h_flex()
            .size_full()
            .items_start()
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .gap(px(10.))
                    .pr(t.gutter)
                    .pb(px(12.))
                    .child(self.header(cx))
                    .child(filter)
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .w_full()
                            .relative()
                            .overflow_hidden()
                            .border_t_1()
                            .border_b_1()
                            .border_color(t.row_rule)
                            .child(body)
                            .when(self.loading, |el| el.child(loading_edge("connections-loading"))),
                    )
                    .child(self.status_line()),
            )
            .when_some(panel, |el, p| el.child(p))
    }
}

/// Nodes per kind on the map.
fn shown(model: &MapModel) -> Vec<(NodeKind, usize)> {
    NodeKind::ALL.iter().map(|k| (*k, model.view.nodes.iter().filter(|n| n.node.kind() == *k).count())).collect()
}
