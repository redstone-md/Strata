//! One event record reduced to what the timeline needs: System fields and data pairs.

use super::binxml::{Element, Node};
use strata_kernel::Timestamp;

#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct EventRecord {
    pub(super) record_id: u64,
    pub(super) event_id: Option<u32>,
    pub(super) provider: String,
    pub(super) channel: String,
    pub(super) computer: String,
    pub(super) time: Option<Timestamp>,
    /// `EventData/Data` (`Name` → value; unnamed data has an empty name) and `UserData` leaves.
    pub(super) data: Vec<(String, String)>,
}

impl EventRecord {
    /// Build from the parsed record XML; `written` (record header time) is the fallback time.
    pub(super) fn from_nodes(record_id: u64, written: Option<Timestamp>, nodes: &[Node]) -> Option<Self> {
        let event = find(nodes, "Event")?;
        let mut rec = EventRecord { record_id, time: written, ..Default::default() };
        if let Some(system) = event.child("System") {
            rec.event_id = system.child("EventID").and_then(|e| e.text().trim().parse().ok());
            rec.provider = system
                .child("Provider")
                .and_then(|p| p.attr_text("Name").filter(|n| !n.is_empty()).or_else(|| p.attr_text("EventSourceName")))
                .unwrap_or_default();
            rec.channel = system.child("Channel").map(Element::text).unwrap_or_default();
            rec.computer = system.child("Computer").map(Element::text).unwrap_or_default();
            let created = system.child("TimeCreated").and_then(|t| t.attr("SystemTime")).and_then(first_time);
            rec.time = created.or(written);
        }
        if let Some(data) = event.child("EventData") {
            for d in data.elements() {
                rec.data.push((d.attr_text("Name").unwrap_or_default(), d.text()));
            }
        }
        if let Some(user) = event.child("UserData") {
            for holder in user.elements() {
                for leaf in holder.elements() {
                    rec.data.push((leaf.name.clone(), leaf.text()));
                }
            }
        }
        Some(rec)
    }

    /// Value of a named data item (case-insensitive name).
    pub(super) fn get(&self, name: &str) -> Option<&str> {
        self.data.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty() && *v != "-")
    }

    /// Unnamed data items in order (classic-style events such as MsiInstaller).
    pub(super) fn unnamed(&self) -> impl Iterator<Item = &str> {
        self.data.iter().filter(|(n, v)| n.is_empty() && !v.is_empty()).map(|(_, v)| v.as_str())
    }

    /// `name=value; …` summary for the detail line, capped.
    pub(super) fn summary(&self) -> String {
        let parts: Vec<String> = self
            .data
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .take(24)
            .map(|(n, v)| if n.is_empty() { v.clone() } else { format!("{n}={v}") })
            .collect();
        let s = parts.join("; ");
        match s.char_indices().nth(600) {
            Some((i, _)) => format!("{}…", &s[..i]),
            None => s,
        }
    }
}

fn first_time(values: &[Node]) -> Option<Timestamp> {
    values.iter().find_map(|n| match n {
        Node::Value(v) => v.time(),
        _ => None,
    })
}

/// First element called `name`, searching through anonymous wrapper elements.
fn find<'n>(nodes: &'n [Node], name: &str) -> Option<&'n Element> {
    nodes.iter().find_map(|n| match n {
        Node::Element(e) if e.name == name => Some(e),
        Node::Element(e) if e.name.is_empty() => find(&e.children, name),
        _ => None,
    })
}
