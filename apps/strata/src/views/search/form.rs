//! The query form: what to look for, how, in which encodings and where; and running it.

use super::{Area, Mode, NAME_LIMIT, SearchView};
use crate::theme::tokens;
use crate::widgets::{Check, Choice, Field, TextButton, quiet};
use gpui::{Context, IntoElement, ParentElement, SharedString, Styled, Window, div, prelude::FluentBuilder as _, px};
use gpui_component::{h_flex, v_flex};
use strata_workbench::{Encoding, Pattern, Scope, SearchQuery, SearchRecord};

const LABEL_WIDTH: f32 = 84.;
const REGEX_NOTE: &str =
    "Regex is slower than text: every byte goes through the pattern engine, and UTF-16 text is decoded first when a UTF-16 encoding is ticked.";

/// One line about a stored search: state, count, and whether the cap was hit.
pub fn status_line(r: &SearchRecord) -> String {
    let state = match r.state.as_str() {
        "running" => "Searching".to_string(),
        "done" => "Done".to_string(),
        "cancelled" => "Cancelled".to_string(),
        other => other.to_string(),
    };
    let more = if r.truncated { ", the limit; refine the query to see the rest" } else { "" };
    format!("{state}: {} matches{more}. {}", r.results, r.summary)
}

fn shorten(text: &str) -> String {
    let short: String = text.chars().take(32).collect();
    if short.len() < text.len() { format!("{short}…") } else { short }
}

impl SearchView {
    fn build_query(&self, text: &str) -> Result<SearchQuery, String> {
        let pattern = match self.mode {
            Mode::Hex => Pattern::hex(text)?,
            Mode::Regex => Pattern::Regex(text.to_string()),
            _ => Pattern::Text(text.to_string()),
        };
        if self.encodings.is_empty() && self.mode != Mode::Hex {
            return Err("Tick at least one encoding.".into());
        }
        let scope = match self.area {
            Area::Disk => Scope::WholeDisk,
            Area::Free => Scope::Unallocated,
            Area::Deleted => Scope::DeletedFiles,
            Area::Volume(n) => Scope::Volume(n),
        };
        Ok(SearchQuery { pattern, encodings: self.encodings.clone(), case_insensitive: self.case_insensitive, scope })
    }

    pub(super) fn run(&mut self, cx: &mut Context<Self>) {
        let text = self.query_text(cx).trim().to_string();
        if text.is_empty() {
            self.status = Some("Type something to search for.".into());
            return cx.notify();
        }
        let wb = self.session.read(cx).workbench().clone();
        if self.mode == Mode::Names {
            let rows = wb.find_files_by_name(&text, self.disk, NAME_LIMIT).unwrap_or_default();
            let disks = self.session.read(cx).snapshot().disks.iter().map(|d| (d.id(), d.record.info.label.clone())).collect();
            let n = rows.len();
            self.names.update(cx, |t, cx| {
                t.delegate_mut().set_rows(rows, disks);
                t.refresh(cx);
            });
            let more = if n == NAME_LIMIT { " (the first ones; narrow the pattern)" } else { "" };
            self.status = Some(format!("{n} files named like \"{text}\"{more}, deleted and orphaned entries included.").into());
            return cx.notify();
        }
        let started = self.build_query(&text).and_then(|q| wb.start_search(q, self.disk).map_err(|e| e.to_string()));
        match started {
            Ok((_, search)) => {
                self.search = Some(search);
                self.selected = None;
                self.status = Some("Searching…".into());
                self.results.update(cx, |t, cx| {
                    t.delegate_mut().show(Some(search));
                    t.refresh(cx);
                });
                self.session.update(cx, |s, cx| s.watch_jobs(cx));
            }
            Err(e) => self.status = Some(e.into()),
        }
        cx.notify();
    }

    fn run_label(&self, text: &str) -> String {
        match (self.mode, text.trim().is_empty()) {
            (Mode::Names, _) => "Find files".into(),
            (_, true) => "Search the disk".into(),
            (_, false) => format!("Search the disk for \u{201C}{}\u{201D}", shorten(text.trim())),
        }
    }

    fn label(text: &'static str) -> impl IntoElement {
        let t = tokens();
        div().w(px(LABEL_WIDTH)).flex_shrink_0().text_size(t.size_body).text_color(t.text_secondary).child(text)
    }

    fn encodings_row(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let checks = Encoding::ALL.into_iter().map(|e| {
            let on = self.encodings.contains(&e);
            Check::new(SharedString::from(format!("enc-{}", e.key())), e.name(), on, cx.listener(move |this, _, _, cx| {
                if on {
                    this.encodings.retain(|x| *x != e);
                } else {
                    this.encodings.push(e);
                }
                cx.notify();
            }))
        });
        let case = Check::new("match-case", "Match case", !self.case_insensitive, cx.listener(|this, _, _, cx| {
            this.case_insensitive = !this.case_insensitive;
            cx.notify();
        }));
        h_flex()
            .gap(px(12.))
            .items_start()
            .child(Self::label("Encodings"))
            .child(h_flex().flex_1().min_w_0().flex_wrap().gap(px(18.)).gap_y_2().pl(px(4.)).children(checks).child(case))
    }

    fn scope_row(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let snapshot = self.session.read(cx).snapshot();
        let disks: Vec<(strata_workbench::EvidenceId, String)> = snapshot.disks.iter().map(|d| (d.id(), d.record.info.label.clone())).collect();
        let volumes: Vec<u32> = self
            .disk
            .and_then(|id| snapshot.disks.iter().find(|d| d.id() == id))
            .map(|d| d.record.volumes.iter().map(|v| v.index).collect())
            .unwrap_or_default();
        let mut areas = vec![Area::Disk, Area::Free, Area::Deleted];
        areas.extend(volumes.iter().map(|v| Area::Volume(*v)));
        let area_labels = areas
            .iter()
            .map(|a| match a {
                Area::Disk => "Whole disk".into(),
                Area::Free => "Free space".into(),
                Area::Deleted => "Deleted files".into(),
                Area::Volume(n) => format!("Volume {n}").into(),
            })
            .collect();
        let selected_area = areas.iter().position(|a| *a == self.area).unwrap_or(0);
        let mut disk_labels: Vec<SharedString> = vec!["All disks".into()];
        disk_labels.extend(disks.iter().map(|(_, l)| SharedString::from(l.clone())));
        let selected_disk = self.disk.and_then(|id| disks.iter().position(|(d, _)| *d == id)).map_or(0, |i| i + 1);
        let this = cx.entity().downgrade();
        let pick_area = move |i: usize, _: &mut Window, cx: &mut gpui::App| {
            let _ = this.update(cx, |v, cx| {
                v.area = areas.get(i).copied().unwrap_or(Area::Disk);
                cx.notify();
            });
        };
        let this = cx.entity().downgrade();
        let pick_disk = move |i: usize, _: &mut Window, cx: &mut gpui::App| {
            let _ = this.update(cx, |v, cx| {
                v.disk = i.checked_sub(1).and_then(|i| disks.get(i)).map(|(id, _)| *id);
                if matches!(v.area, Area::Volume(_)) {
                    v.area = Area::Disk;
                }
                cx.notify();
            });
        };
        let t = tokens();
        let hex = self.results.read(cx).delegate().hex;
        h_flex()
            .flex_wrap()
            .gap(px(12.))
            .gap_y_2()
            .child(Self::label("Look in"))
            .child(Choice::new("area", area_labels, selected_area, pick_area))
            .when(disk_labels.len() > 2, |el| {
                el.child(div().text_size(t.size_body).text_color(t.text_secondary).child("on")).child(Choice::new("disk", disk_labels, selected_disk, pick_disk))
            })
            .child(div().flex_1())
            .child(TextButton::new("context-hex", if hex { "Context as text" } else { "Context as hex" }).on_click(cx.listener(|this, _, _, cx| {
                this.results.update(cx, |t, cx| {
                    t.delegate_mut().hex = !t.delegate().hex;
                    t.refresh(cx);
                });
                cx.notify();
            })))
    }

    pub(super) fn form(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let _ = window;
        let t = tokens();
        let text = self.query_text(cx);
        let modes = Mode::ALL.iter().map(|m| SharedString::from(m.label())).collect();
        let selected = Mode::ALL.iter().position(|m| *m == self.mode).unwrap_or(0);
        let this = cx.entity().downgrade();
        let pick_mode = move |i: usize, _: &mut Window, cx: &mut gpui::App| {
            let _ = this.update(cx, |v, cx| {
                v.mode = Mode::ALL.get(i).copied().unwrap_or(Mode::Text);
                v.status = None;
                cx.notify();
            });
        };
        let count = match self.mode {
            Mode::Names => None,
            _ => {
                let d = self.results.read(cx).delegate();
                (d.len() > 0 && d.has_more_rows()).then(|| format!("showing the first {}, scroll for more", d.len()))
            }
        };
        v_flex()
            .gap(px(12.))
            .max_w(t.content_max_width)
            .child(
                h_flex()
                    .h(px(32.))
                    .gap(px(16.))
                    .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child("Search"))
                    .children(self.status.clone().map(|s| div().min_w_0().text_size(t.size_body).text_color(t.text).truncate().child(s)))
                    .children(count.map(|c| quiet().flex_shrink_0().child(c))),
            )
            .child(
                h_flex()
                    .flex_wrap()
                    .gap(px(12.))
                    .gap_y_2()
                    .child(div().w(px(LABEL_WIDTH)).flex_shrink_0().text_size(t.size_body).text_color(t.text_secondary).child("Find"))
                    .child(div().flex_1().min_w(px(240.)).max_w(px(560.)).child(Field::new(&self.input).data()))
                    .child(Choice::new("mode", modes, selected, pick_mode))
                    .child(TextButton::new("run-search", self.run_label(&text)).strong().on_click(cx.listener(|this, _, _, cx| this.run(cx)))),
            )
            .when(!matches!(self.mode, Mode::Hex | Mode::Names), |el| el.child(self.encodings_row(cx)))
            .when(self.mode != Mode::Names, |el| el.child(self.scope_row(cx)))
            .when(self.mode == Mode::Regex, |el| el.child(h_flex().child(div().w(px(LABEL_WIDTH + 12.))).child(quiet().child(REGEX_NOTE))))
            .when(self.mode == Mode::Names, |el| {
                el.child(h_flex().child(div().w(px(LABEL_WIDTH + 12.))).child(quiet().child("Matches names of every indexed entry, deleted and orphaned ones too. Use * and ? for patterns, like *.dat.")))
            })
    }
}
