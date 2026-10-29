//! How a node looks on the map, decided once per load: shape by kind, size and brightness by
//! score, and the few states worth a second glance (coins, the owner, deleted). Monochrome:
//! only shape, outline, fill tone and dashes tell nodes apart.

use crate::theme::{grey, tokens};
use gpui::Hsla;
use strata_workbench::{Node, NodeKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Identities.
    Circle,
    /// Accounts.
    RoundSquare,
    /// Services.
    Hexagon,
    /// Keys, seeds and wallets.
    Square,
    /// Addresses.
    Diamond,
    /// Files: a page, taller than wide.
    Page,
    /// Disks: a wide slab.
    Slab,
    /// Messages: an envelope.
    Envelope,
    /// Leads.
    Triangle,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Look {
    pub shape: Shape,
    /// Half the size in pixels at zoom 1.
    pub radius: f32,
    /// `None` draws the outline only (over the ground, hiding lines underneath).
    pub fill: Option<Hsla>,
    pub stroke: Hsla,
    /// A second outline: the likely owner, an address holding coins.
    pub ring: bool,
    pub dashed: bool,
}

/// Brightness of a node's marks: dim for low scores, near white for the best.
pub fn tone(score: f32) -> f32 {
    0.40 + 0.52 * (score / 100.0).clamp(0.0, 1.0)
}

pub fn radius(score: f32) -> f32 {
    5.0 + 6.0 * (score / 100.0).clamp(0.0, 1.0)
}

pub fn look(node: &Node) -> Look {
    let t = tokens();
    let (score, flags) = (node.score(), node.flags());
    let stroke = grey(tone(score));
    let plain = |shape| Look { shape, radius: radius(score), fill: None, stroke, ring: false, dashed: false };
    match node.kind() {
        NodeKind::Identity if flags.owner => Look { fill: Some(t.emphasis), stroke: t.emphasis, ring: true, ..plain(Shape::Circle) },
        NodeKind::Identity => plain(Shape::Circle),
        NodeKind::Account => plain(Shape::RoundSquare),
        NodeKind::Service => Look { radius: 9.0, ..plain(Shape::Hexagon) },
        NodeKind::Secret => Look { fill: Some(stroke), ..plain(Shape::Square) },
        NodeKind::Address if flags.funded => Look { fill: Some(t.emphasis), stroke: t.emphasis, ring: true, radius: radius(score) + 1.0, ..plain(Shape::Diamond) },
        NodeKind::Address if flags.used => Look { fill: Some(grey(0.62)), ..plain(Shape::Diamond) },
        NodeKind::Address => plain(Shape::Diamond),
        NodeKind::File => Look { dashed: flags.deleted, ..plain(Shape::Page) },
        NodeKind::Disk => Look { radius: 10.0, fill: Some(t.ink), stroke: t.text_secondary, ..plain(Shape::Slab) },
        NodeKind::Message => plain(Shape::Envelope),
        NodeKind::Lead if score >= 60.0 => Look { fill: Some(stroke), ..plain(Shape::Triangle) },
        NodeKind::Lead => plain(Shape::Triangle),
    }
}

/// The look a kind has in the legend (a mid-ranked node of that kind).
pub fn legend(kind: NodeKind) -> Look {
    let t = tokens();
    let stroke = t.text;
    let base = Look { shape: Shape::Circle, radius: 5.0, fill: None, stroke, ring: false, dashed: false };
    match kind {
        NodeKind::Identity => base,
        NodeKind::Account => Look { shape: Shape::RoundSquare, ..base },
        NodeKind::Service => Look { shape: Shape::Hexagon, ..base },
        NodeKind::Secret => Look { shape: Shape::Square, fill: Some(stroke), ..base },
        NodeKind::Address => Look { shape: Shape::Diamond, ..base },
        NodeKind::File => Look { shape: Shape::Page, ..base },
        NodeKind::Disk => Look { shape: Shape::Slab, fill: Some(t.ink), stroke: t.text_secondary, ..base },
        NodeKind::Message => Look { shape: Shape::Envelope, ..base },
        NodeKind::Lead => Look { shape: Shape::Triangle, ..base },
    }
}

/// A label short enough for the map: long values keep both ends (`1BgGZ9…26SAMH`), other text
/// is cut at the end.
pub fn short_label(node: &Node) -> String {
    shorten(node.label(), node.kind())
}

fn shorten(label: &str, kind: NodeKind) -> String {
    let chars: Vec<char> = label.chars().collect();
    let max = match kind {
        NodeKind::Lead | NodeKind::Message => 34,
        _ => 26,
    };
    if chars.len() <= max {
        return label.to_string();
    }
    let middle = matches!(kind, NodeKind::Address | NodeKind::Secret) && !label.contains(' ');
    if middle {
        crate::format::middle(label, 17)
    } else {
        format!("{}…", chars[..max - 1].iter().collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brighter_and_larger_with_score() {
        assert!(tone(90.0) > tone(20.0) && tone(150.0) <= 0.92 + f32::EPSILON);
        assert!(radius(90.0) > radius(10.0));
    }

    #[test]
    fn shortens_long_values_in_the_middle() {
        assert_eq!(shorten("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", NodeKind::Address), "1BgGZ9tc…Z26SAMH");
        assert_eq!(shorten("olga@example.ru", NodeKind::Identity), "olga@example.ru");
        assert_eq!(shorten("a very long lead title that goes on and on", NodeKind::Lead).chars().count(), 34);
    }

    #[test]
    fn every_kind_has_its_own_shape() {
        let mut shapes: Vec<Shape> = NodeKind::ALL.iter().map(|k| legend(*k).shape).collect();
        shapes.dedup();
        assert_eq!(shapes.len(), NodeKind::ALL.len());
    }
}
