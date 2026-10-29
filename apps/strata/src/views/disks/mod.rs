//! Disks: add images or drives, then each disk with its map, volumes, when it was in use and
//! the computers found on it. Machine profiles and usage load off the UI thread after every
//! analysis; raw host facts only load when asked for.

mod detail;
mod facts;
mod machine;
pub(crate) mod usage;

use super::disk_row::DiskRow;
use crate::nav::Navigate;
use crate::picker::{PickKind, pick_path};
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{Check, DiskMaps, Field, Section, TextButton, loading_edge, quiet, rule};
use gpui::{
    App, AppContext as _, Context, Entity, EventEmitter, IntoElement, ParentElement, Render, SharedString, Styled, Subscription,
    Window, div, prelude::FluentBuilder as _, px,
};
use gpui_component::input::{InputEvent, InputState};
use gpui_component::{h_flex, v_flex};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use strata_workbench::{DiskMachines, EvidenceId, FactGroup};

/// Left indent of a disk's details (under the disk's facts column of [`DiskRow`]).
const DETAIL_INDENT: f32 = 244.;

pub struct DisksView {
    session: Entity<Session>,
    maps: Entity<DiskMaps>,
    path: Entity<InputState>,
    message: Option<SharedString>,
    machines: HashMap<EvidenceId, DiskMachines>,
    /// Grouped raw facts of disks whose "Show all facts" is on (loaded on demand).
    facts: HashMap<EvidenceId, Vec<FactGroup>>,
    show_facts: HashSet<EvidenceId>,
    open_keys: HashMap<EvidenceId, Vec<String>>,
    loading: bool,
    loads: u64,
    was_active: bool,
    known_disks: usize,
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
        let mut this = Self {
            session,
            maps,
            path,
            message: None,
            machines: HashMap::new(),
            facts: HashMap::new(),
            show_facts: HashSet::new(),
            open_keys: HashMap::new(),
            loading: false,
            loads: 0,
            was_active: false,
            known_disks: 0,
            deep: false,
            _subscriptions: subscriptions,
        };
        this.reload(cx);
        this
    }

    /// Reload when a run of jobs ends or disks come and go — not on every progress tick.
    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let snapshot = self.session.read(cx).snapshot();
        let active = snapshot.active_jobs().next().is_some();
        let disks = snapshot.disks.len();
        if (self.was_active && !active) || disks != self.known_disks {
            self.reload(cx);
        }
        self.was_active = active;
        cx.notify();
    }

    /// Build every disk's machines and usage on a background thread.
    fn reload(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let wb = session.workbench().clone();
        let ids: Vec<EvidenceId> = session.snapshot().disks.iter().map(|d| d.id()).collect();
        self.known_disks = ids.len();
        self.loads += 1;
        self.loading = true;
        let ticket = self.loads;
        cx.spawn(async move |this, cx| {
            let found = cx
                .background_executor()
                .spawn(async move { ids.into_iter().filter_map(|id| Some((id, wb.machines(id).ok()?))).collect::<HashMap<_, _>>() })
                .await;
            let _ = this.update(cx, |v, cx| {
                if v.loads != ticket {
                    return;
                }
                v.loading = false;
                v.machines = found;
                // Facts may have changed with the machines; lists that are shown load again.
                v.facts.clear();
                for id in v.show_facts.clone() {
                    v.load_facts(id, cx);
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn load_facts(&mut self, id: EvidenceId, cx: &mut Context<Self>) {
        let wb = self.session.read(cx).workbench().clone();
        cx.spawn(async move |this, cx| {
            let groups = cx.background_executor().spawn(async move { wb.fact_groups(id, facts::OPEN_VALUES).unwrap_or_default() }).await;
            let _ = this.update(cx, |v, cx| {
                v.facts.insert(id, groups);
                cx.notify();
            });
        })
        .detach();
    }

    fn toggle_facts(&mut self, id: EvidenceId, cx: &mut Context<Self>) {
        if !self.show_facts.remove(&id) {
            self.show_facts.insert(id);
            if !self.facts.contains_key(&id) {
                self.load_facts(id, cx);
            }
        }
        cx.notify();
    }

    fn toggle_key(&mut self, id: EvidenceId, key: String, cx: &mut Context<Self>) {
        let open = self.open_keys.entry(id).or_default();
        match open.iter().position(|k| *k == key) {
            Some(i) => {
                open.remove(i);
            }
            None => open.push(key),
        }
        cx.notify();
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

    /// Machine cards, then the raw facts toggle and (when on) the grouped facts.
    fn machines_section(&self, id: EvidenceId, cx: &mut Context<Self>) -> Option<Section> {
        let found = self.machines.get(&id)?;
        let shown = self.show_facts.contains(&id);
        let this = cx.entity().downgrade();
        let toggle = TextButton::new(SharedString::from(format!("facts-{id}")), if shown { "Hide all facts" } else { "Show all facts" })
            .on_click(move |_, _, cx| {
                let _ = this.update(cx, |v, cx| v.toggle_facts(id, cx));
            });
        let note = match found.machines.len() {
            0 => "none found yet; the Artifacts step reads the system files".to_string(),
            1 => "1 installation".to_string(),
            n => format!("{n} installations"),
        };
        let this = cx.entity().downgrade();
        let on_key: Rc<dyn Fn(String, &mut Window, &mut App)> = Rc::new(move |key, _, cx| {
            let _ = this.update(cx, |v, cx| v.toggle_key(id, key, cx));
        });
        let open = self.open_keys.get(&id).cloned().unwrap_or_default();
        let raw = shown.then(|| match self.facts.get(&id) {
            Some(groups) => facts::list(id.get(), groups, &open, on_key).into_any_element(),
            None => quiet().child("Loading facts…").into_any_element(),
        });
        Some(
            Section::new("Machines")
                .note(note)
                .aside(toggle)
                .child(h_flex().flex_wrap().items_start().gap(px(40.)).gap_y(px(28.)).children(found.machines.iter().map(machine::card)))
                .children(raw),
        )
    }
}

impl Render for DisksView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let snapshot = self.session.read(cx).snapshot().clone();
        let disks: Vec<_> = snapshot
            .disks
            .iter()
            .map(|d| {
                let busy = snapshot.active_jobs().any(|j| j.evidence == d.id());
                let usage = self.machines.get(&d.id()).map(|m| m.usage.clone());
                let row = DiskRow::new(d.clone(), self.maps.read(cx).get(d.id()), self.session.clone(), busy)
                    .usage(usage.as_ref().and_then(usage::short_range).map(SharedString::from));
                let volumes = detail::volumes(&d.record, {
                    let this = cx.entity().downgrade();
                    let id = d.id();
                    move |volume, _, cx| {
                        let _ = this.update(cx, |_, cx| cx.emit(Navigate::files(id, volume)));
                    }
                });
                v_flex()
                    .gap(t.block_gap)
                    .child(rule())
                    .child(row)
                    .child(
                        h_flex()
                            .items_start()
                            .flex_wrap()
                            .gap(px(56.))
                            .gap_y(t.block_gap)
                            .pl(px(DETAIL_INDENT))
                            .children(volumes)
                            .children(usage.as_ref().map(usage::section)),
                    )
                    .children(self.machines_section(d.id(), cx).map(|s| div().pl(px(DETAIL_INDENT)).child(s)))
            })
            .collect();
        v_flex()
            .w_full()
            .max_w(t.content_max_width)
            .gap(t.section_gap)
            .relative()
            .when(self.loading, |el| el.child(loading_edge("disks-loading")))
            .child(self.add_section(cx))
            .children(disks)
    }
}
