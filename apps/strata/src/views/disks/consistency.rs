//! Evidence consistency of one disk: the verdict, then each observation with its severity, a
//! plain explanation and the numbers behind it. Alerts and warnings are inverted badges,
//! notices outlined, context lines quiet.

use crate::theme::tokens;
use crate::widgets::{Badge, Section, quiet};
use gpui::{IntoElement, ParentElement, Styled, div, px};
use gpui_component::{h_flex, v_flex};
use strata_workbench::{Assessment, Observation, Severity, VerdictKind};

/// Width of the severity column.
const SEVERITY_WIDTH: f32 = 64.;
/// Widest an explanation runs before wrapping.
const TEXT_WIDTH: f32 = 720.;

/// The verdict as a short badge for disk rows (their facts column is narrow): inverted when
/// the disk needs a closer look.
pub fn verdict_badge(a: &Assessment) -> Option<Badge> {
    let warnings = a.at_least(Severity::Warning).count();
    Some(match a.verdict.kind {
        VerdictKind::NotAnalysed => return None,
        VerdictKind::NormallyUsed if warnings == 0 => Badge::outline("normal use"),
        VerdictKind::NormallyUsed => Badge::outline(format!("normal use · {warnings} warnings")),
        VerdictKind::LittleUse => Badge::inverted("little use"),
        VerdictKind::WipedOrReinstalled => Badge::inverted(match a.verdict.since {
            Some(t) => format!("wiped/reinstalled {}", t.to_string().chars().take(10).collect::<String>()),
            None => "wiped/reinstalled".to_string(),
        }),
        VerdictKind::Unreadable => Badge::inverted("file system not read"),
    })
}

pub fn severity_badge(s: Severity) -> Option<Badge> {
    match s {
        Severity::Alert | Severity::Warning => Some(Badge::inverted(s.label())),
        Severity::Notice => Some(Badge::outline(s.label())),
        Severity::Info => None,
    }
}

/// `Volume size 298 GB · Live files 24 · Coverage 0.03%`.
pub fn figures_line(o: &Observation) -> String {
    o.figures.iter().map(|f| format!("{} {}", f.label, f.value)).collect::<Vec<_>>().join("  ·  ")
}

fn observation(o: &Observation) -> impl IntoElement {
    let t = tokens();
    let info = o.severity == Severity::Info;
    let figures = figures_line(o);
    h_flex()
        .items_start()
        .gap(px(12.))
        .py(px(8.))
        .border_b_1()
        .border_color(t.row_rule)
        .child(h_flex().w(px(SEVERITY_WIDTH)).flex_shrink_0().pt(px(1.)).children(severity_badge(o.severity)))
        .child(
            v_flex()
                .min_w_0()
                .max_w(px(TEXT_WIDTH))
                .gap(px(3.))
                .child(div().text_size(t.size_body).text_color(if info { t.text } else { t.emphasis }).child(o.title.clone()))
                .child(div().text_size(t.size_body).text_color(t.text_secondary).child(o.explanation.clone()))
                .children((!figures.is_empty()).then(|| div().text_size(t.size_small).font_family(t.font_data).text_color(t.text).child(figures))),
        )
}

/// The disk's consistency section.
pub fn section(a: &Assessment) -> impl IntoElement {
    let t = tokens();
    let lead = match a.verdict.kind {
        VerdictKind::NormallyUsed | VerdictKind::NotAnalysed => {
            h_flex().child(div().text_size(t.size_body).text_color(t.emphasis).child(a.verdict.headline.clone()))
        }
        _ => h_flex().child(Badge::inverted(a.verdict.headline.clone())),
    };
    let body = if a.observations.is_empty() {
        quiet().child("Nothing unusual in the file index, the dates or the findings.").into_any_element()
    } else {
        v_flex().border_t_1().border_color(t.row_rule).children(a.observations.iter().map(observation)).into_any_element()
    };
    Section::new("Evidence consistency")
        .note("whether what Strata extracted is plausible for this disk")
        .child(lead)
        .child(body)
}
