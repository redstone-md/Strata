//! Renders a detail tree: indented rows with 1px guide lines, disclosure triangles on groups,
//! label left in secondary text, value right, Copy on data values.

use super::node::{Cell, TreeNode};
use crate::format;
use crate::theme::tokens;
use crate::widgets::Badge;
use gpui::{
    AnyElement, App, ClipboardItem, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement as _, Styled, Window, div, prelude::FluentBuilder as _, px, relative,
};
use gpui_component::{Icon, IconName, h_flex, v_flex};
use std::collections::HashMap;
use std::rc::Rc;

const INDENT: f32 = 14.;
const LABEL_WIDTH: f32 = 128.;
const ROW_HEIGHT: f32 = 24.;

/// Groups the user opened or closed, by path; everything else uses the node's default.
pub type TreeState = HashMap<String, bool>;

/// Called with a group's path and whether it should now be open.
type ToggleHandler = Rc<dyn Fn(String, bool, &mut Window, &mut App)>;

#[derive(IntoElement)]
pub struct DetailTree {
    nodes: Vec<TreeNode>,
    state: TreeState,
    on_toggle: ToggleHandler,
}

impl DetailTree {
    pub fn new(nodes: Vec<TreeNode>, state: TreeState, on_toggle: impl Fn(String, bool, &mut Window, &mut App) + 'static) -> Self {
        Self { nodes, state, on_toggle: Rc::new(on_toggle) }
    }

    fn is_open(&self, path: &str, node: &TreeNode) -> bool {
        self.state.get(path).copied().unwrap_or(node.open)
    }

    fn collect(&self, nodes: &[TreeNode], depth: usize, parent: &str, out: &mut Vec<AnyElement>) {
        for (i, node) in nodes.iter().enumerate() {
            let path = format!("{parent}/{i}:{}", node.label);
            let open = node.is_group() && self.is_open(&path, node);
            out.push(self.row(node, depth, &path, open));
            if open {
                self.collect(&node.children, depth + 1, &path, out);
            }
        }
    }

    fn cell(cell: &Cell) -> AnyElement {
        let t = tokens();
        let text = |s: &str, color| div().min_w_0().text_size(t.size_body).text_color(color).whitespace_normal().child(s.to_string());
        match cell {
            Cell::Text(s) => text(s, t.text).into_any_element(),
            Cell::Quiet(s) => text(s, t.text_secondary).into_any_element(),
            Cell::Data(s) => text(s, t.text).font_family(t.font_data).into_any_element(),
            Cell::Badge(s, true) => h_flex().child(Badge::inverted(s.clone())).into_any_element(),
            Cell::Badge(s, false) => h_flex().child(Badge::outline(s.clone())).into_any_element(),
            Cell::Bar(f) => h_flex()
                .gap(px(8.))
                .child(div().w(px(96.)).h(px(2.)).bg(t.rule).child(div().h_full().w(relative(f.clamp(0.0, 1.0))).bg(t.emphasis)))
                .child(text(&format::percent(*f), t.text))
                .into_any_element(),
        }
    }

    fn copy_button(path: &str, value: String) -> impl IntoElement {
        let t = tokens();
        div()
            .id(SharedString::from(format!("copy{path}")))
            .flex_shrink_0()
            .px(px(4.))
            .rounded(t.radius)
            .text_size(t.size_small)
            .text_color(t.text_secondary)
            .cursor_pointer()
            .hover(|s| s.bg(t.hover).text_color(t.emphasis))
            .child("Copy")
            .on_click(move |_, _, cx| {
                cx.stop_propagation();
                cx.write_to_clipboard(ClipboardItem::new_string(value.clone()));
            })
    }

    fn row(&self, node: &TreeNode, depth: usize, path: &str, open: bool) -> AnyElement {
        let t = tokens();
        let guides = (0..depth).map(|d| div().absolute().top_0().bottom_0().left(px(d as f32 * INDENT + 5.)).w(px(1.)).bg(t.rule));
        let indent = px(depth as f32 * INDENT);
        let base = h_flex().id(SharedString::from(format!("row{path}"))).relative().w_full().min_h(px(ROW_HEIGHT)).items_start().children(guides);
        if node.note {
            let text = match &node.cell {
                Some(Cell::Text(s)) => s.clone(),
                _ => String::new(),
            };
            return base
                .child(
                    div()
                        .ml(indent + px(INDENT))
                        .my(px(3.))
                        .px(px(6.))
                        .py(px(2.))
                        .border_1()
                        .border_color(t.text_secondary)
                        .rounded(t.radius)
                        .text_size(t.size_small)
                        .text_color(t.text)
                        .child(text),
                )
                .into_any_element();
        }
        let group = node.is_group();
        let disclosure = div().w(px(INDENT)).h(px(ROW_HEIGHT)).flex_shrink_0().flex().items_center().when(group, |el| {
            el.child(Icon::new(if open { IconName::ChevronDown } else { IconName::ChevronRight }).size(px(12.)).text_color(t.text_secondary))
        });
        let label_width = (LABEL_WIDTH - depth as f32 * INDENT).max(64.);
        let label = div()
            .when(!node.label.is_empty(), |el| el.w(px(label_width)))
            .flex_shrink_0()
            .py(px(4.))
            .pr(px(8.))
            .text_size(t.size_body)
            .text_color(if group { t.text } else { t.text_secondary })
            .child(node.label.clone());
        let value = div().flex_1().min_w_0().py(px(4.)).children(node.cell.as_ref().map(Self::cell));
        let copy = node.copy.clone().map(|v| div().py(px(3.)).child(Self::copy_button(path, v)));
        let row = base.pl(indent).child(disclosure).child(label).child(value).children(copy);
        if !group {
            return row.into_any_element();
        }
        let (toggle, key) = (self.on_toggle.clone(), path.to_string());
        row.cursor_pointer()
            .hover(|s| s.bg(t.hover))
            .on_click(move |_, window, cx| toggle(key.clone(), !open, window, cx))
            .into_any_element()
    }
}

impl RenderOnce for DetailTree {
    fn render(self, _: &mut Window, _: &mut App) -> impl IntoElement {
        let mut rows = Vec::new();
        self.collect(&self.nodes, 0, "", &mut rows);
        v_flex().w_full().children(rows)
    }
}
