//! The map canvas: links, nodes and labels of one laid-out view. Drag pans, the wheel zooms
//! around the cursor, hovering a node lights its neighbourhood and dims the rest, a click
//! selects and a double-click re-centres.

use super::look::{self, Look};
use super::paint::{self, Camera};
use crate::theme::{grey, tokens};
use gpui::{
    App, Bounds, DispatchPhase, IntoElement, MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, Pixels, Point, ScrollEvent,
    SharedString, Styled as _, Window, canvas, px,
};
use std::cell::Cell;
use std::rc::Rc;
use strata_workbench::{EdgeKind, GraphView, Layout};

/// Nodes at or above this score are always labelled.
const LABEL_SCORE: f32 = 45.0;
/// Small views label everything.
const LABEL_ALL_BELOW: usize = 28;
/// Pointer travel that turns a press into a drag instead of a click.
const DRAG_SLOP: f32 = 4.0;

/// One laid-out view with everything painting needs, computed once per load.
pub struct MapModel {
    pub view: GraphView,
    pub layout: Layout,
    pub looks: Vec<Look>,
    pub labels: Vec<SharedString>,
    pub neighbours: Vec<Vec<usize>>,
}

impl MapModel {
    pub fn new(view: GraphView, layout: Layout) -> Self {
        let looks = view.nodes.iter().map(|n| look::look(&n.node)).collect();
        let labels = view
            .nodes
            .iter()
            .map(|n| SharedString::from(if n.more > 0 { format!("{}  +{}", look::short_label(&n.node), n.more) } else { look::short_label(&n.node) }))
            .collect();
        let neighbours = (0..view.nodes.len()).map(|i| view.neighbours(i)).collect();
        Self { view, layout, looks, labels, neighbours }
    }

    fn point(&self, i: usize) -> (f32, f32) {
        self.layout.point(i).unwrap_or_default()
    }

    /// The node under a screen position, if any.
    fn hit(&self, camera: Camera, canvas: Bounds<Pixels>, at: Point<Pixels>) -> Option<usize> {
        let scale = camera.mark_scale();
        (0..self.view.nodes.len())
            .map(|i| {
                let p = camera.screen(canvas, self.point(i));
                (i, (p.x - at.x).as_f32().hypot((p.y - at.y).as_f32()))
            })
            .filter(|(i, d)| *d <= self.looks[*i].radius * scale + 5.0)
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(i, _)| i)
    }
}

#[derive(Clone, Copy)]
struct Drag {
    last: Point<Pixels>,
    travelled: f32,
}

/// Pointer and camera state shared between paints.
#[derive(Default)]
pub struct MapState {
    pub camera: Cell<Camera>,
    pub hovered: Cell<Option<usize>>,
    /// Fit the drawing to the canvas on the next paint (after a load).
    pub fit: Cell<bool>,
    drag: Cell<Option<Drag>>,
}

/// What the view marks besides hover: the selected node and search matches.
#[derive(Default)]
pub struct Marks {
    pub selected: Option<usize>,
    pub matches: Vec<usize>,
}

/// Called with the node clicked (`None` for empty space) and whether it was a double-click.
pub type Pick = Rc<dyn Fn(Option<usize>, bool, &mut Window, &mut App)>;

pub fn map(model: Rc<MapModel>, state: Rc<MapState>, marks: Rc<Marks>, on_pick: Pick) -> impl IntoElement {
    canvas(
        |_, _, _| (),
        move |bounds, (), window, cx| {
            if state.fit.replace(false)
                && let Some(b) = model.layout.bounds()
            {
                state.camera.set(Camera::fit(b, bounds.size.width.as_f32(), bounds.size.height.as_f32()));
            }
            paint_map(&model, &state, &marks, bounds, window, cx);
            listen(model.clone(), state.clone(), on_pick.clone(), bounds, window);
        },
    )
    .size_full()
}

fn paint_map(model: &MapModel, state: &MapState, marks: &Marks, bounds: Bounds<Pixels>, window: &mut Window, cx: &mut App) {
    let t = tokens();
    let camera = state.camera.get();
    let scale = camera.mark_scale();
    let n = model.view.nodes.len();
    let pos: Vec<Point<Pixels>> = (0..n).map(|i| camera.screen(bounds, model.point(i))).collect();
    let focus = state.hovered.get().or(marks.selected).filter(|f| *f < n);
    let near = |i: usize| focus.is_none_or(|f| f == i || model.neighbours[f].contains(&i));
    for e in &model.view.edges {
        let touches = focus.is_some_and(|f| e.from == f || e.to == f);
        let color = if touches { t.text } else { grey(0.38).opacity(if focus.is_some() { 0.3 } else { 1.0 }) };
        let width = if e.kind.strength() >= 0.9 { 1.4 } else { 1.0 };
        paint::link(window, pos[e.from], pos[e.to], width, color, matches!(e.kind, EdgeKind::OnDisk | EdgeKind::OnService));
    }
    // Least important first, so the best nodes sit on top.
    for i in (0..n).rev() {
        paint::node(window, pos[i], &model.looks[i], scale, if near(i) { 1.0 } else { 0.28 });
    }
    for (i, dashed) in marks.selected.iter().map(|s| (*s, false)).chain(marks.matches.iter().map(|m| (*m, true))) {
        if let Some(p) = pos.get(i) {
            let r = model.looks[i].radius * scale + 7.0;
            let ring = Bounds::new(gpui::point(p.x - px(r), p.y - px(r)), gpui::size(px(r * 2.0), px(r * 2.0)));
            let style = if dashed { gpui::BorderStyle::Dashed } else { gpui::BorderStyle::Solid };
            window.paint_quad(gpui::quad(ring, px(r), gpui::transparent_black(), px(1.), t.emphasis, style));
        }
    }
    let all = n <= LABEL_ALL_BELOW || camera.zoom >= 1.3;
    // Marked nodes first, then by score: where labels would collide, the better one wins.
    let marked = |i: usize| Some(i) == focus || Some(i) == model.view.centre || marks.selected == Some(i) || marks.matches.contains(&i);
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|a, b| marked(*b).cmp(&marked(*a)).then(model.view.nodes[*b].node.score().total_cmp(&model.view.nodes[*a].node.score())));
    let mut taken = Vec::new();
    for i in order {
        let node = &model.view.nodes[i];
        let marked = marked(i);
        let neighbour = focus.is_some_and(|f| model.neighbours[f].contains(&i));
        if !(all || marked || neighbour || node.node.score() >= LABEL_SCORE) || (focus.is_some() && !near(i)) {
            continue;
        }
        let l = &model.looks[i];
        let reach = match l.shape {
            look::Shape::Slab => 1.5,
            look::Shape::Diamond => 1.25,
            _ => 1.0,
        };
        let r = l.radius * scale * reach + if l.ring { 4.0 } else { 0.0 };
        let at = gpui::point(pos[i].x + px(r + 6.0), pos[i].y);
        let color = if marked { t.emphasis } else if neighbour { t.text } else { t.text_secondary };
        let font = if matches!(node.node.kind(), strata_workbench::NodeKind::Lead | strata_workbench::NodeKind::Message | strata_workbench::NodeKind::Disk | strata_workbench::NodeKind::Service) {
            t.font_ui
        } else {
            t.font_data
        };
        paint::label(window, cx, &mut taken, model.labels[i].clone(), at, font, 11.0, color);
    }
}

fn listen(model: Rc<MapModel>, state: Rc<MapState>, on_pick: Pick, bounds: Bounds<Pixels>, window: &mut Window) {
    let (m, s) = (model.clone(), state.clone());
    window.on_mouse_event(move |e: &MouseMoveEvent, phase, window, _| {
        if phase != DispatchPhase::Bubble {
            return;
        }
        if let Some(mut drag) = s.drag.get() {
            if e.pressed_button == Some(MouseButton::Left) {
                let (dx, dy) = ((e.position.x - drag.last.x).as_f32(), (e.position.y - drag.last.y).as_f32());
                let mut camera = s.camera.get();
                camera.pan = (camera.pan.0 + dx, camera.pan.1 + dy);
                s.camera.set(camera);
                drag = Drag { last: e.position, travelled: drag.travelled + dx.abs() + dy.abs() };
                s.drag.set(Some(drag));
                window.refresh();
                return;
            }
            s.drag.set(None);
        }
        let hit = if bounds.contains(&e.position) { m.hit(s.camera.get(), bounds, e.position) } else { None };
        if s.hovered.get() != hit {
            s.hovered.set(hit);
            window.refresh();
        }
    });
    let (m, s, pick) = (model.clone(), state.clone(), on_pick.clone());
    window.on_mouse_event(move |e: &MouseDownEvent, phase, window, cx| {
        if phase != DispatchPhase::Bubble || e.button != MouseButton::Left || !bounds.contains(&e.position) {
            return;
        }
        s.drag.set(Some(Drag { last: e.position, travelled: 0.0 }));
        if e.click_count == 2
            && let Some(i) = m.hit(s.camera.get(), bounds, e.position)
        {
            pick(Some(i), true, window, cx);
        }
    });
    let (m, s) = (model, state.clone());
    window.on_mouse_event(move |e: &MouseUpEvent, phase, window, cx| {
        if phase != DispatchPhase::Bubble || e.button != MouseButton::Left {
            return;
        }
        if let Some(drag) = s.drag.take()
            && drag.travelled < DRAG_SLOP
            && bounds.contains(&e.position)
            && e.click_count < 2
        {
            on_pick(m.hit(s.camera.get(), bounds, e.position), false, window, cx);
        }
    });
    window.on_mouse_event(move |e: &ScrollEvent, phase, window, _| {
        if phase != DispatchPhase::Bubble || !bounds.contains(&e.position) {
            return;
        }
        let dy = e.delta.pixel_delta(px(20.)).y.as_f32();
        let c = bounds.center();
        let mut camera = state.camera.get();
        camera.zoom_at((dy * 0.004).exp(), ((e.position.x - c.x).as_f32(), (e.position.y - c.y).as_f32()));
        state.camera.set(camera);
        window.refresh();
    });
}
