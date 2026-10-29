//! Minimize, maximize/restore and close, drawn in the app's style. On Windows the buttons are
//! native caption areas (snap layouts, double-click and keyboard behave as usual); elsewhere
//! they act on click.

use crate::theme::tokens;
use gpui::{
    App, InteractiveElement as _, IntoElement, ParentElement, RenderOnce, StatefulInteractiveElement as _, Styled,
    Window, WindowControlArea, div, prelude::FluentBuilder as _, px,
};
use gpui_component::{Icon, IconName, h_flex};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Control {
    Minimize,
    Zoom,
    Close,
}

impl Control {
    fn area(self) -> WindowControlArea {
        match self {
            Self::Minimize => WindowControlArea::Min,
            Self::Zoom => WindowControlArea::Max,
            Self::Close => WindowControlArea::Close,
        }
    }

    fn act(self, window: &mut Window) {
        match self {
            Self::Minimize => window.minimize_window(),
            Self::Zoom => window.zoom_window(),
            Self::Close => window.remove_window(),
        }
    }
}

#[derive(IntoElement)]
pub struct WindowControls;

impl WindowControls {
    fn button(control: Control, icon: IconName) -> impl IntoElement {
        let t = tokens();
        // Close inverts on hover instead of turning red.
        let (hover_bg, hover_fg) = if control == Control::Close { (t.text, t.ink) } else { (t.hover, t.text) };
        div()
            .id(match control {
                Control::Minimize => "window-minimize",
                Control::Zoom => "window-zoom",
                Control::Close => "window-close",
            })
            .occlude()
            .w(px(46.))
            .h_full()
            .flex()
            .items_center()
            .justify_center()
            .text_color(t.text_secondary)
            .hover(move |s| s.bg(hover_bg).text_color(hover_fg))
            .when(cfg!(target_os = "windows"), |el| el.window_control_area(control.area()))
            .when(!cfg!(target_os = "windows"), |el| el.on_click(move |_, window, _| control.act(window)))
            .child(Icon::new(icon).size(px(16.)))
    }
}

impl RenderOnce for WindowControls {
    fn render(self, window: &mut Window, _: &mut App) -> impl IntoElement {
        let zoom = if window.is_maximized() { IconName::WindowRestore } else { IconName::WindowMaximize };
        h_flex()
            .h_full()
            .flex_shrink_0()
            .child(Self::button(Control::Minimize, IconName::WindowMinimize))
            .child(Self::button(Control::Zoom, zoom))
            .child(Self::button(Control::Close, IconName::WindowClose))
    }
}
