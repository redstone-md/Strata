//! Disks: add images or drives, then each disk with its map, volumes and what the
//! artefacts say about the machine it came from.

mod detail;

use super::disk_row::DiskRow;
use crate::picker::{PickKind, pick_path};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{Check, DiskMaps, Field, Section, TextButton, rule};
use crate::nav::Navigate;
use gpui::{
    AppContext as _, Context, Entity, EventEmitter, IntoElement, ParentElement, Render, SharedString, Styled, Subscription,
    Window, div, px,
};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{h_flex, v_flex};
use std::collections::HashMap;
use strata_workbench::{EvidenceId, HostFact};

pub struct DisksView {
    session: Entity<Session>,
    maps: Entity<DiskMaps>,
    path: Entity<InputState>,
    message: Option<SharedString>,
    facts: HashMap<EvidenceId, Vec<HostFact>>,
    /// Probe old CHS layouts for deleted partitions when adding.
    deep: bool,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<Navigate> for DisksView {}

impl DisksView {
    pub fn new(session: Entity<Session>, maps: Entity<DiskMaps>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let path = cx.new(|cx| InputState::new(window, cx).placeholder(r"D:\images\laptop.img  or  \\.\PhysicalDrive1"));
        let subscriptions = vec![
            cx.observe(&session, |this, _, cx| this.on_session_changed(cx)),
            cx.subscribe_in(&path, window, |this, _, event: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = event {
                    this.add(window, cx);
                }
            }),
        ];
        let mut this =
            Self { session, maps, path, message: None, facts: HashMap::new(), deep: false, _subscriptions: subscriptions };
        this.load_facts(cx);
        this
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let active = self.session.read(cx).snapshot().active_jobs().next().is_some();
        if !active {
            self.load_facts(cx);
        }
        cx.notify();
    }

    fn load_facts(&mut self, cx: &mut Context<Self>) {
        let wb = self.session.read(cx).workbench().clone();
        let mut facts: HashMap<EvidenceId, Vec<HostFact>> = HashMap::new();
        for f in wb.host_facts(None).unwrap_or_default() {
            facts.entry(f.evidence).or_default().push(f);
        }
        self.facts = facts;
    }

    fn add(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let location = self.path.read(cx).value().to_string();
        let deep = self.deep;
        let result = self.session.update(cx, |s, cx| s.add_evidence(&location, deep, cx));
        self.message = Some(match result {
            Ok(()) => {
                self.path.update(cx, |p, cx| p.set_value("", window, cx));
                format!("Added {}. Press Analyse to index and scan it.", location.trim()).into()
            }
            Err(e) => format!("Could not add the disk: {e}. Check the path and that the file is readable.").into(),
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

    fn add_section(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        Section::new("Add disk image or drive")
            .note("Raw images (.img, .dd, .001), R-Studio images (.rdr) or a physical drive. Opened read-only.")
            .child(
                h_flex()
                    .gap(px(8.))
                    .max_w(px(880.))
                    .child(div().flex_1().child(Field::new(&self.path).data()))
                    .child(TextButton::new("browse", "Browse").on_click(cx.listener(|this, _, window, cx| this.browse(window, cx))))
                    .child(TextButton::new("add", "Add").strong().on_click(cx.listener(|this, _, window, cx| this.add(window, cx)))),
            )
            .child(Check::new("deep-sweep", "Deep partition sweep: also look for deleted partitions at old cylinder boundaries", self.deep, cx.listener(|this, _, _, cx| {
                this.deep = !this.deep;
                cx.notify();
            })))
            .children(self.message.clone().map(|m| div().text_size(t.size_body).text_color(t.text).child(m)))
    }
}

impl Render for DisksView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let snapshot = self.session.read(cx).snapshot().clone();
        let maps = self.maps.read(cx);
        let disks: Vec<_> = snapshot
            .disks
            .iter()
            .map(|d| {
                let busy = snapshot.active_jobs().any(|j| j.evidence == d.id());
                let facts = self.facts.get(&d.id()).map(Vec::as_slice).unwrap_or_default();
                v_flex()
                    .gap(t.block_gap)
                    .child(rule())
                    .child(DiskRow::new(d.clone(), maps.get(d.id()), self.session.clone(), busy))
                    .child(
                        h_flex()
                            .items_start()
                            .gap(px(56.))
                            .pl(px(244.))
                            .children(detail::volumes(&d.record, {
                                let this = cx.entity().downgrade();
                                let id = d.id();
                                move |volume, _, cx| {
                                    let _ = this.update(cx, |_, cx| cx.emit(Navigate::files(id, volume)));
                                }
                            }))
                            .children((!facts.is_empty()).then(|| detail::machine(facts))),
                    )
            })
            .collect();
        v_flex()
            .w_full()
            .max_w(t.content_max_width)
            .gap(t.section_gap)
            .child(self.add_section(cx))
            .children(disks)
    }
}
