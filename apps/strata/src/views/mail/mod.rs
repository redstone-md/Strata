//! Mail: messages read from mail files (live and deleted) and carved from free space, with
//! the selected message beside the list. The command-bar search filters by text, or by
//! address when it is a whole e-mail address (the Accounts screen jumps here that way).

mod delegate;
mod detail;

use crate::format;
use crate::session::Session;
use crate::theme::tokens;
use crate::widgets::{TextButton, flat_table, loading_edge};
use delegate::MailDelegate;
use detail::MailDetail;
use gpui::{
    AppContext as _, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Subscription, Window, div,
    prelude::FluentBuilder as _, px,
};
use gpui_component::table::{TableEvent, TableState};
use gpui_component::{h_flex, v_flex};
use std::collections::HashMap;
use strata_workbench::{MessageState, StoredMessage};

/// A whole address (`local@domain.tld`, nothing else) searches by address, not by text.
fn as_address(text: &str) -> Option<String> {
    let (local, domain) = text.split_once('@')?;
    let plain = |s: &str| !s.is_empty() && !s.contains(char::is_whitespace) && !s.contains('@');
    (plain(local) && plain(domain) && domain.contains('.')).then(|| text.to_lowercase())
}

pub struct MailView {
    session: Entity<Session>,
    table: Entity<TableState<MailDelegate>>,
    selected: Option<StoredMessage>,
    /// Outcome of the last export from the detail panel.
    note: Option<SharedString>,
    all_headers: bool,
    total: u64,
    generation: u64,
    was_active: bool,
    /// Bumped per reload / selection; a slower earlier load that lands late is dropped.
    loads: u64,
    picks: u64,
    loading: bool,
    _subscriptions: Vec<Subscription>,
}

impl MailView {
    pub fn new(session: Entity<Session>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let workbench = session.read(cx).workbench().clone();
        let table = cx.new(|cx| TableState::new(MailDelegate::new(workbench), window, cx).col_movable(false));
        let subscriptions = vec![
            cx.subscribe_in(&table, window, |this, table, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(ix) = event
                    && let Some(id) = table.read(cx).delegate().row(*ix).map(|r| r.id)
                {
                    this.open(id, cx);
                }
            }),
            cx.observe(&session, |this, _, cx| this.on_session_changed(cx)),
        ];
        let generation = session.read(cx).generation();
        let mut this = Self {
            session,
            table,
            selected: None,
            note: None,
            all_headers: false,
            total: 0,
            generation,
            was_active: false,
            loads: 0,
            picks: 0,
            loading: false,
            _subscriptions: subscriptions,
        };
        this.reload(cx);
        this
    }

    fn on_session_changed(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let active = session.snapshot().active_jobs().next().is_some();
        if session.generation() != self.generation {
            self.generation = session.generation();
            let wb = session.workbench().clone();
            self.selected = None;
            self.table.update(cx, |t, _| t.delegate_mut().set_workbench(wb));
            self.reload(cx);
        } else if self.was_active && !active {
            self.reload(cx);
        }
        self.was_active = active;
    }

    pub fn set_search(&mut self, text: &str, cx: &mut Context<Self>) {
        let text = text.trim();
        let address = as_address(text);
        let text = Some(text.to_string()).filter(|t| !t.is_empty() && address.is_none());
        self.table.update(cx, |t, _| {
            let q = t.delegate_mut().query_mut();
            q.text = text;
            q.address = address;
        });
        self.reload(cx);
    }

    /// Query the first page and the total on a background thread, then show them.
    fn reload(&mut self, cx: &mut Context<Self>) {
        let session = self.session.read(cx);
        let disks: HashMap<_, _> = session.snapshot().disks.iter().map(|d| (d.id(), d.record.info.label.clone())).collect();
        let wb = session.workbench().clone();
        let query = self.table.read(cx).delegate().first_page();
        self.loads += 1;
        self.loading = true;
        let ticket = self.loads;
        cx.spawn(async move |this, cx| {
            let (rows, total) = cx
                .background_executor()
                .spawn(async move { (wb.messages(&query).unwrap_or_default(), wb.message_count(&query).unwrap_or_default()) })
                .await;
            let _ = this.update(cx, |v, cx| {
                if v.loads != ticket {
                    return;
                }
                v.loading = false;
                v.total = total;
                v.table.update(cx, |t, cx| {
                    t.delegate_mut().set_rows(disks, rows);
                    t.refresh(cx);
                    cx.notify();
                });
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    /// Load one message (body, headers, places) off the UI thread and show it.
    fn open(&mut self, id: i64, cx: &mut Context<Self>) {
        let wb = self.session.read(cx).workbench().clone();
        self.picks += 1;
        let ticket = self.picks;
        self.note = None;
        cx.spawn(async move |this, cx| {
            let message = cx.background_executor().spawn(async move { wb.message(id).ok().flatten() }).await;
            let _ = this.update(cx, |v, cx| {
                if v.picks == ticket {
                    v.selected = message;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    /// Ask for a folder, then write the message or one attachment there.
    fn export(&mut self, attachment: Option<usize>, cx: &mut Context<Self>) {
        let Some(id) = self.selected.as_ref().map(|m| m.row.id) else { return };
        let this = cx.entity().downgrade();
        crate::picker::pick_path(crate::picker::PickKind::Folder, cx, move |dest, cx| {
            let _ = this.update(cx, |v, cx| {
                let wb = v.session.read(cx).workbench().clone();
                let result = match attachment {
                    Some(i) => wb.export_attachment(id, i, &dest),
                    None => wb.export_message(id, &dest),
                };
                v.note = Some(
                    match result {
                        Ok(r) => format!("Written to {}{}", r.written_to.display(), if r.partial { " (partial)" } else { "" }),
                        Err(e) => format!("Could not export: {e}"),
                    }
                    .into(),
                );
                cx.notify();
            });
        });
    }

    fn header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let d = self.table.read(cx).delegate();
        let n = d.len() as u64;
        let count = if d.has_more_rows() { format!("first {n} of {}, scroll for more", self.total) } else { format::count(n, "message", "messages") };
        let state = self.table.read(cx).delegate().state();
        let toggle = |id: &'static str, label: &'static str, value: Option<MessageState>, cx: &mut Context<Self>| {
            let chosen = state == value;
            let button = TextButton::new(id, label).on_click(cx.listener(move |this, _, _, cx| this.show_state(value, cx)));
            if chosen { button.strong() } else { button }
        };
        h_flex()
            .h(px(32.))
            .gap(px(16.))
            .items_center()
            .text_size(t.size_body)
            .child(div().text_size(t.size_heading).font_weight(t.semibold).text_color(t.emphasis).child("Mail"))
            .child(div().text_color(t.text_secondary).child(count))
            .child(div().flex_1())
            .child(
                h_flex()
                    .gap(px(6.))
                    .child(toggle("mail-all", "All", None, cx))
                    .child(toggle("mail-live", "Live", Some(MessageState::Live), cx))
                    .child(toggle("mail-deleted", "Deleted", Some(MessageState::Deleted), cx))
                    .child(toggle("mail-carved", "Carved", Some(MessageState::Carved), cx)),
            )
    }

    fn show_state(&mut self, state: Option<MessageState>, cx: &mut Context<Self>) {
        self.table.update(cx, |t, _| t.delegate_mut().query_mut().state = state);
        self.reload(cx);
    }
}

impl Render for MailView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens();
        let detail = self.selected.clone().map(|m| {
            let disk = self.table.read(cx).delegate().disk_label(m.row.evidence);
            let (close, toggle, export, attach) =
                (cx.entity().downgrade(), cx.entity().downgrade(), cx.entity().downgrade(), cx.entity().downgrade());
            MailDetail::new(m, disk, self.note.clone(), self.all_headers)
                .on_close(move |_, _, cx| {
                    let _ = close.update(cx, |v, cx| {
                        v.selected = None;
                        cx.notify();
                    });
                })
                .on_toggle_headers(move |_, _, cx| {
                    let _ = toggle.update(cx, |v, cx| {
                        v.all_headers = !v.all_headers;
                        cx.notify();
                    });
                })
                .on_export(move |_, _, cx| {
                    let _ = export.update(cx, |v, cx| v.export(None, cx));
                })
                .on_attachment(move |i, _, cx| {
                    let _ = attach.update(cx, |v, cx| v.export(Some(i), cx));
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
                    .gap(px(12.))
                    .pr(t.gutter)
                    .child(self.header(cx))
                    .child(
                        div()
                            .flex_1()
                            .min_h_0()
                            .size_full()
                            .relative()
                            .child(flat_table(&self.table))
                            .when(self.loading, |el| el.child(loading_edge("mail-loading"))),
                    ),
            )
            .when_some(detail, |el, d| el.child(d))
    }
}

#[cfg(test)]
mod tests {
    use super::as_address;

    #[test]
    fn whole_addresses_search_by_address() {
        assert_eq!(as_address("Anna@Example.com"), Some("anna@example.com".into()));
        assert_eq!(as_address("@example.com"), None);
        assert_eq!(as_address("anna@localhost"), None);
        assert_eq!(as_address("from anna@example.com"), None);
        assert_eq!(as_address("wallet"), None);
    }
}
