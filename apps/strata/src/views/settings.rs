//! Settings: switch case, chain backend endpoint (persisted in a later iteration).

use crate::picker::{PickKind, pick_path};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{GlassCard, Glyph, SearchField};
use gpui::{
    AppContext as _, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Subscription,
    Window, div,
};
use gpui_component::button::{Button, ButtonVariants as _};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{Icon, h_flex, v_flex};

pub struct SettingsView {
    session: Entity<Session>,
    case_path: Entity<InputState>,
    endpoint: Entity<InputState>,
    message: Option<(bool, SharedString)>,
    _subscriptions: Vec<Subscription>,
}

impl SettingsView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let case_path = cx.new(|cx| InputState::new(window, cx).placeholder(r"C:\Cases\laptop.strata"));
        let endpoint = cx.new(|cx| InputState::new(window, cx).placeholder("https://mempool.space/api"));
        let subscriptions = vec![
            cx.observe(&session, |_, _, cx| cx.notify()),
            cx.subscribe_in(&case_path, window, |this, _, event: &InputEvent, _, cx| {
                if let InputEvent::PressEnter { .. } = event {
                    this.open_case(cx);
                }
            }),
        ];
        Self { session, case_path, endpoint, message: None, _subscriptions: subscriptions }
    }

    fn open_case(&mut self, cx: &mut Context<Self>) {
        let raw = self.case_path.read(cx).value().to_string();
        let path = std::path::PathBuf::from(raw.trim().trim_matches('"'));
        if path.as_os_str().is_empty() {
            self.message = Some((true, "Enter a case folder".into()));
        } else {
            let result = self.session.update(cx, |s, cx| s.switch_case(&path, cx));
            self.message = Some(match result {
                Ok(()) => (false, format!("Opened {}", path.display()).into()),
                Err(e) => (true, e.into()),
            });
        }
        cx.notify();
    }

    fn browse(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let input = self.case_path.downgrade();
        let window = window.window_handle();
        pick_path(PickKind::Folder, cx, move |path, cx| {
            let _ = window.update(cx, |_, window, cx| {
                let _ = input.update(cx, |p, cx| p.set_value(path.display().to_string(), window, cx));
            });
        });
    }
}

impl Render for SettingsView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let current = self.session.read(cx).case_root().display().to_string();
        let message = self.message.clone().map(|(err, text)| {
            div().text_size(t.size_caption).text_color(if err { t.red } else { t.green }).child(text)
        });
        v_flex()
            .gap(t.gap)
            .max_w(gpui::px(900.))
            .child(
                GlassCard::new()
                    .title("Case")
                    .subtitle("A case is a folder; it is created if missing.")
                    .child(
                        h_flex()
                            .gap_2()
                            .text_sm()
                            .child(div().text_color(t.text_muted).child("Current"))
                            .child(div().text_color(t.text).truncate().child(current)),
                    )
                    .child(
                        h_flex()
                            .gap_3()
                            .child(div().flex_1().child(SearchField::new(&self.case_path).glyph(Glyph::FolderOpen)))
                            .child(
                                Button::new("case-browse")
                                    .ghost()
                                    .label("Browse…")
                                    .on_click(cx.listener(|this, _, window, cx| this.browse(window, cx))),
                            )
                            .child(
                                Button::new("case-open")
                                    .primary()
                                    .icon(Icon::new(Glyph::FolderOpen))
                                    .label("Open case")
                                    .on_click(cx.listener(|this, _, _, cx| this.open_case(cx))),
                            ),
                    )
                    .children(message),
            )
            .child(
                GlassCard::new()
                    .title("Chain balance backend")
                    .subtitle("Endpoint used to look up balances of recovered addresses. Not saved yet.")
                    .child(SearchField::new(&self.endpoint).glyph(Glyph::Globe)),
            )
    }
}
