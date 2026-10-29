//! Settings: which case is open, where balances are looked up, and report export.

use crate::picker::{PickKind, pick_path};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{Check, Field, Section, TextButton, mono};
use gpui::{
    AppContext as _, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Subscription, Window,
    div, px,
};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{h_flex, v_flex};

const REPORT_FORMATS: [(&str, &str); 4] = [("html", "HTML"), ("md", "Markdown"), ("csv", "CSV"), ("json", "JSON")];

/// Which section a status message belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Topic {
    Case,
    Chain,
    Report,
}

pub struct SettingsView {
    session: Entity<Session>,
    case_path: Entity<InputState>,
    endpoint: Entity<InputState>,
    /// Session generation the endpoint field was last filled from.
    endpoint_generation: Option<u64>,
    message: Option<(Topic, SharedString)>,
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
            cx.subscribe_in(&endpoint, window, |this, _, event: &InputEvent, _, cx| {
                if let InputEvent::PressEnter { .. } = event {
                    this.save_endpoint(cx);
                }
            }),
        ];
        Self { session, case_path, endpoint, endpoint_generation: None, message: None, _subscriptions: subscriptions }
    }

    fn say(&mut self, topic: Topic, text: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.message = Some((topic, text.into()));
        cx.notify();
    }

    fn open_case(&mut self, cx: &mut Context<Self>) {
        let raw = self.case_path.read(cx).value().to_string();
        let path = std::path::PathBuf::from(raw.trim().trim_matches('"'));
        if path.as_os_str().is_empty() {
            return self.say(Topic::Case, "Enter a case folder, or press Browse.", cx);
        }
        let text = match self.session.update(cx, |s, cx| s.switch_case(&path, cx)) {
            Ok(()) => format!("Opened {}", path.display()),
            Err(e) => format!("Could not open {}: {e}", path.display()),
        };
        self.say(Topic::Case, text, cx);
    }

    fn save_endpoint(&mut self, cx: &mut Context<Self>) {
        let url = self.endpoint.read(cx).value().trim().to_string();
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return self.say(Topic::Chain, "Enter a full URL starting with https://", cx);
        }
        let text = match self.session.read(cx).workbench().set_chain_endpoint(&url) {
            Ok(()) => "Saved. The next balance check uses this endpoint.".to_string(),
            Err(e) => format!("Could not save the endpoint: {e}"),
        };
        self.say(Topic::Chain, text, cx);
    }

    fn export(&mut self, format: &'static str, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let dir = session.case_root().join("reports");
        let text = match session.workbench().export_report(format, &dir) {
            Ok(path) => format!("Saved {}", path.display()),
            Err(e) => format!("Could not write the report: {e}"),
        };
        self.say(Topic::Report, text, cx);
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

    /// Fill the endpoint field from the open case (again after a case switch).
    fn sync_endpoint(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        if self.endpoint_generation == Some(session.generation()) {
            return;
        }
        self.endpoint_generation = Some(session.generation());
        let url = session.workbench().chain_endpoint();
        self.endpoint.update(cx, |e, cx| e.set_value(url, window, cx));
    }

    fn message(&self, topic: Topic) -> Option<impl IntoElement> {
        let t = tokens();
        self.message
            .as_ref()
            .filter(|(m, _)| *m == topic)
            .map(|(_, text)| div().text_size(t.size_body).text_color(t.text).child(text.clone()))
    }
}

impl Render for SettingsView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        self.sync_endpoint(window, cx);
        let current = self.session.read(cx).case_root().display().to_string();
        let show_raw = self.session.read(cx).show_raw();
        let exports = REPORT_FORMATS.map(|(format, label)| {
            TextButton::new(SharedString::from(format!("export-{format}")), label)
                .on_click(cx.listener(move |this, _, _, cx| this.export(format, cx)))
        });
        v_flex()
            .gap(t.section_gap)
            .max_w(px(880.))
            .child(
                Section::new("Case")
                    .note("A case is a folder. Opening a folder that does not exist creates it.")
                    .child(
                        h_flex()
                            .gap(px(12.))
                            .text_size(t.size_body)
                            .child(div().text_color(t.text_secondary).child("Open now"))
                            .child(mono().text_color(t.text).truncate().child(current)),
                    )
                    .child(
                        h_flex()
                            .gap(px(8.))
                            .child(div().flex_1().child(Field::new(&self.case_path).data()))
                            .child(TextButton::new("case-browse", "Browse").on_click(cx.listener(|this, _, window, cx| this.browse(window, cx))))
                            .child(TextButton::new("case-open", "Open case").strong().on_click(cx.listener(|this, _, _, cx| this.open_case(cx)))),
                    )
                    .children(self.message(Topic::Case)),
            )
            .child(
                Section::new("Balance lookups")
                    .note("Esplora endpoint used to check recovered addresses on chain. Saved with the case.")
                    .child(
                        h_flex()
                            .gap(px(8.))
                            .child(div().flex_1().child(Field::new(&self.endpoint).data()))
                            .child(TextButton::new("endpoint-save", "Save").strong().on_click(cx.listener(|this, _, _, cx| this.save_endpoint(cx)))),
                    )
                    .children(self.message(Topic::Chain)),
            )
            .child(
                Section::new("Findings")
                    .note("Raw data is the detector output behind each finding, for checking a mapping.")
                    .child(Check::new("show-raw", "Show raw data under each finding", show_raw, cx.listener(|this, _, _, cx| {
                        this.session.update(cx, |s, cx| s.set_show_raw(!s.show_raw(), cx));
                    }))),
            )
            .child(
                Section::new("Report")
                    .note("Everything found so far, written to the reports folder of the case.")
                    .child(h_flex().gap(px(8.)).children(exports))
                    .children(self.message(Topic::Report)),
            )
    }
}
