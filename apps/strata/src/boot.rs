//! Startup: the window opens at once with a splash while the case is opened on a background
//! thread, then the workbench fades in. Opening a large case (database recovery, the first
//! snapshot, resuming jobs) takes seconds; the window never stops answering meanwhile.

use crate::session::{Opening, Session};
use crate::shell::{Shell, WindowControls};
use crate::theme::tokens;
use crate::view_state::WindowPlacement;
use crate::widgets::{loading_line, scan_grid};
use gpui::{
    Animation, AnimationExt as _, AnyElement, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Render, Styled as _, Window, WindowControlArea, div, ease_out_quint, px,
};
use gpui_component::{h_flex, v_flex};
use std::path::PathBuf;
use std::time::Duration;

/// Elapsed time is shown once opening takes longer than this.
const SHOW_ELAPSED_AFTER: Duration = Duration::from_secs(2);

/// The splash body: the logo grid scanning, the case name and what is happening now.
pub fn splash(opening: &Opening) -> impl IntoElement {
    let t = tokens();
    let elapsed = opening.started.elapsed();
    let step = match elapsed >= SHOW_ELAPSED_AFTER {
        true => format!("{}, {} s", opening.progress.step(), elapsed.as_secs()),
        false => opening.progress.step().to_string(),
    };
    div().size_full().flex().items_center().justify_center().child(
        v_flex()
            .items_center()
            .gap(px(28.))
            .child(scan_grid("splash-grid", 14.))
            .child(
                v_flex()
                    .items_center()
                    .gap(px(6.))
                    .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child(format!("Opening {}", opening.name)))
                    .child(div().text_size(t.size_body).text_color(t.text_secondary).child(step)),
            )
            .child(div().w(px(220.)).child(loading_line("splash-line"))),
    )
}

enum Stage {
    Opening(Opening),
    Ready { session: Entity<Session>, shell: Entity<Shell> },
}

pub struct Boot {
    stage: Stage,
}

impl Boot {
    pub fn new(case: PathBuf, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let opening = Opening::new(&case);
        let progress = opening.progress.clone();
        cx.spawn_in(window, async move |this, cx| {
            let opened = cx.background_executor().spawn(async move { Session::open(&case, &progress) }).await;
            let _ = this.update_in(cx, |boot, window, cx| {
                let session = cx.new(|cx| Session::new(opened, cx));
                let shell = cx.new(|cx| Shell::new(session.clone(), window, cx));
                shell.update(cx, |s, cx| s.restore(window, cx));
                boot.stage = Stage::Ready { session, shell };
                cx.notify();
            });
        })
        .detach();
        Self { stage: Stage::Opening(opening) }
    }

    /// The window is closing: keep the work. View state is saved and running jobs stop at a
    /// checkpoint, to resume on the next start.
    pub fn close(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        WindowPlacement::of(window).save();
        if let Stage::Ready { session, shell } = &self.stage {
            shell.update(cx, |s, cx| s.save_view_state(cx));
            session.read(cx).workbench().shutdown(Duration::from_secs(5));
        }
    }

    /// Caption strip for the splash: drag area and window buttons, like the command bar.
    fn caption() -> impl IntoElement {
        let t = tokens();
        h_flex()
            .id("splash-caption")
            .w_full()
            .h(t.command_bar_height)
            .flex_shrink_0()
            .window_control_area(WindowControlArea::Drag)
            .child(div().flex_1())
            .child(WindowControls)
    }
}

impl Render for Boot {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let body: AnyElement = match &self.stage {
            Stage::Opening(opening) => {
                v_flex().size_full().bg(t.ground).child(Self::caption()).child(splash(opening)).into_any_element()
            }
            Stage::Ready { shell, .. } => div()
                .size_full()
                .child(shell.clone())
                .with_animation("shell-in", Animation::new(Duration::from_millis(220)).with_easing(ease_out_quint()), |el, f| {
                    el.opacity(f)
                })
                .into_any_element(),
        };
        div().size_full().bg(t.ground).child(body)
    }
}
